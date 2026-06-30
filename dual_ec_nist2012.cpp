#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace dualec {

class Error final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[nodiscard]] std::string openssl_errors() {
    std::ostringstream out;
    bool first = true;
    for (unsigned long code = ERR_get_error(); code != 0; code = ERR_get_error()) {
        std::array<char, 256> buffer{};
        ERR_error_string_n(code, buffer.data(), buffer.size());
        if (!first) {
            out << "; ";
        }
        out << buffer.data();
        first = false;
    }
    return out.str();
}

void require(bool condition, std::string_view message) {
    if (!condition) {
        const std::string details = openssl_errors();
        if (details.empty()) {
            throw Error(std::string(message));
        }
        throw Error(std::string(message) + ": " + details);
    }
}

using BN_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using BN_CTX_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using EC_GROUP_ptr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
using EC_POINT_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

[[nodiscard]] BN_ptr make_bn() {
    BN_ptr result(BN_new(), BN_free);
    require(result != nullptr, "BN_new failed");
    return result;
}

[[nodiscard]] BN_CTX_ptr make_bn_ctx() {
    BN_CTX_ptr result(BN_CTX_new(), BN_CTX_free);
    require(result != nullptr, "BN_CTX_new failed");
    return result;
}

[[nodiscard]] EC_POINT_ptr make_point(const EC_GROUP* group) {
    EC_POINT_ptr result(EC_POINT_new(group), EC_POINT_free);
    require(result != nullptr, "EC_POINT_new failed");
    return result;
}

[[nodiscard]] BN_ptr bn_from_hex(std::string_view text) {
    BIGNUM* raw = nullptr;
    const std::string value(text);
    require(BN_hex2bn(&raw, value.c_str()) != 0 && raw != nullptr, "BN_hex2bn failed");
    return BN_ptr(raw, BN_free);
}

[[nodiscard]] BN_ptr bn_dup(const BIGNUM* value) {
    BN_ptr result(BN_dup(value), BN_free);
    require(result != nullptr, "BN_dup failed");
    return result;
}

class BitString {
public:
    BitString() = default;

    static BitString from_bytes(std::span<const std::uint8_t> bytes) {
        BitString result;
        result.bytes_.assign(bytes.begin(), bytes.end());
        result.bit_length_ = bytes.size() * 8U;
        return result;
    }

    static BitString from_ascii(std::string_view text) {
        return from_bytes(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
    }

    static BitString zeros(std::size_t bit_length) {
        BitString result;
        result.bit_length_ = bit_length;
        result.bytes_.assign((bit_length + 7U) / 8U, 0U);
        return result;
    }

    static BitString from_bn(const BIGNUM* value, std::size_t bit_length) {
        require(!BN_is_negative(value), "negative BIGNUM cannot become a bit string");
        require(static_cast<std::size_t>(BN_num_bits(value)) <= bit_length,
                "BIGNUM does not fit requested bit length");
        BitString result = zeros(bit_length);
        for (std::size_t i = 0; i < bit_length; ++i) {
            const std::size_t source_bit = bit_length - 1U - i;
            if (BN_is_bit_set(value, static_cast<int>(source_bit)) != 0) {
                result.set_bit(i, true);
            }
        }
        return result;
    }

    [[nodiscard]] BN_ptr to_bn() const {
        if (bit_length_ == 0U) {
            return make_bn();
        }
        BN_ptr result(BN_bin2bn(bytes_.data(), static_cast<int>(bytes_.size()), nullptr), BN_free);
        require(result != nullptr, "BN_bin2bn failed");
        const std::size_t unused = bytes_.size() * 8U - bit_length_;
        if (unused != 0U) {
            require(BN_rshift(result.get(), result.get(), static_cast<int>(unused)) == 1,
                    "BN_rshift failed");
        }
        return result;
    }

    [[nodiscard]] std::size_t bit_length() const noexcept {
        return bit_length_;
    }

    [[nodiscard]] bool empty() const noexcept {
        return bit_length_ == 0U;
    }

    [[nodiscard]] bool is_byte_aligned() const noexcept {
        return (bit_length_ % 8U) == 0U;
    }

    [[nodiscard]] bool bit(std::size_t index) const {
        if (index >= bit_length_) {
            throw Error("bit index out of range");
        }
        const std::size_t byte_index = index / 8U;
        const unsigned bit_index = 7U - static_cast<unsigned>(index % 8U);
        return ((bytes_[byte_index] >> bit_index) & 1U) != 0U;
    }

    void set_bit(std::size_t index, bool value) {
        if (index >= bit_length_) {
            throw Error("bit index out of range");
        }
        const std::size_t byte_index = index / 8U;
        const unsigned bit_index = 7U - static_cast<unsigned>(index % 8U);
        const auto mask = static_cast<std::uint8_t>(1U << bit_index);
        if (value) {
            bytes_[byte_index] |= mask;
        } else {
            bytes_[byte_index] &= static_cast<std::uint8_t>(~mask);
        }
    }

    void push_bit(bool value) {
        if ((bit_length_ % 8U) == 0U) {
            bytes_.push_back(0U);
        }
        const std::size_t index = bit_length_;
        ++bit_length_;
        if (value) {
            set_bit(index, true);
        }
    }

    void append(const BitString& other) {
        if (other.empty()) {
            return;
        }
        if (is_byte_aligned() && other.is_byte_aligned()) {
            bytes_.insert(bytes_.end(), other.bytes_.begin(), other.bytes_.end());
            bit_length_ += other.bit_length_;
            return;
        }
        for (std::size_t i = 0; i < other.bit_length_; ++i) {
            push_bit(other.bit(i));
        }
    }

    [[nodiscard]] BitString slice(std::size_t offset, std::size_t count) const {
        if (offset > bit_length_ || count > bit_length_ - offset) {
            throw Error("bit-string slice out of range");
        }
        BitString result;
        for (std::size_t i = 0; i < count; ++i) {
            result.push_bit(bit(offset + i));
        }
        return result;
    }

    [[nodiscard]] BitString left(std::size_t count) const {
        return slice(0U, count);
    }

    [[nodiscard]] BitString right(std::size_t count) const {
        if (count > bit_length_) {
            throw Error("right() count exceeds bit-string length");
        }
        return slice(bit_length_ - count, count);
    }

    [[nodiscard]] BitString pad8_right() const {
        BitString result = *this;
        while (!result.is_byte_aligned()) {
            result.push_bit(false);
        }
        return result;
    }

    [[nodiscard]] const std::vector<std::uint8_t>& bytes_aligned() const {
        require(is_byte_aligned(), "bit string is not byte aligned");
        return bytes_;
    }

    [[nodiscard]] std::string hex() const {
        std::ostringstream out;
        out << std::hex << std::setfill('0');
        for (const std::uint8_t byte : bytes_) {
            out << std::setw(2) << static_cast<unsigned>(byte);
        }
        if (!is_byte_aligned()) {
            out << "/" << std::dec << bit_length_ << "b";
        }
        return out.str();
    }

    friend bool operator==(const BitString& lhs, const BitString& rhs) {
        if (lhs.bit_length_ != rhs.bit_length_) {
            return false;
        }
        for (std::size_t i = 0; i < lhs.bit_length_; ++i) {
            if (lhs.bit(i) != rhs.bit(i)) {
                return false;
            }
        }
        return true;
    }

private:
    std::vector<std::uint8_t> bytes_;
    std::size_t bit_length_ = 0U;
};

[[nodiscard]] BitString concat(std::initializer_list<std::reference_wrapper<const BitString>> parts) {
    BitString result;
    for (const BitString& part : parts) {
        result.append(part);
    }
    return result;
}

[[nodiscard]] std::array<std::uint8_t, 32> sha256(std::span<const std::uint8_t> input) {
    std::array<std::uint8_t, 32> output{};
    unsigned output_length = 0U;
    EVP_MD_CTX_ptr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(context != nullptr, "EVP_MD_CTX_new failed");
    require(EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1,
            "EVP_DigestInit_ex failed");
    require(EVP_DigestUpdate(context.get(), input.data(), input.size()) == 1,
            "EVP_DigestUpdate failed");
    require(EVP_DigestFinal_ex(context.get(), output.data(), &output_length) == 1,
            "EVP_DigestFinal_ex failed");
    require(output_length == output.size(), "unexpected SHA-256 output length");
    return output;
}

// NIST SP 800-90A (January 2012), section 10.4.1.
[[nodiscard]] BitString hash_df(const BitString& input_string, std::size_t bits_to_return) {
    require(input_string.is_byte_aligned(), "Hash_df input must be byte aligned in this implementation");
    require(bits_to_return > 0U, "Hash_df output length must be nonzero");
    require(bits_to_return <= 255U * 256U, "Hash_df output exceeds 255 digest blocks");
    require(bits_to_return <= std::numeric_limits<std::uint32_t>::max(),
            "Hash_df output length exceeds 32-bit encoding");

    const std::uint32_t requested = static_cast<std::uint32_t>(bits_to_return);
    const std::array<std::uint8_t, 4> requested_be{
        static_cast<std::uint8_t>((requested >> 24U) & 0xffU),
        static_cast<std::uint8_t>((requested >> 16U) & 0xffU),
        static_cast<std::uint8_t>((requested >> 8U) & 0xffU),
        static_cast<std::uint8_t>(requested & 0xffU),
    };

    const std::size_t blocks = (bits_to_return + 255U) / 256U;
    BitString temp;
    const auto& input_bytes = input_string.bytes_aligned();
    for (std::size_t i = 1U; i <= blocks; ++i) {
        std::vector<std::uint8_t> message;
        message.reserve(1U + requested_be.size() + input_bytes.size());
        message.push_back(static_cast<std::uint8_t>(i));
        message.insert(message.end(), requested_be.begin(), requested_be.end());
        message.insert(message.end(), input_bytes.begin(), input_bytes.end());
        const auto digest = sha256(message);
        temp.append(BitString::from_bytes(digest));
    }
    return temp.left(bits_to_return);
}

enum class CurveId {
    p256,
    p384,
    p521,
};

struct CurveDefinition {
    CurveId id;
    const char* name;
    int nid;
    std::size_t seedlen;
    std::size_t outlen;
    unsigned max_security_strength;
    const char* qx;
    const char* qy;
};

constexpr CurveDefinition CURVE_P256{
    CurveId::p256,
    "P-256",
    NID_X9_62_prime256v1,
    256U,
    240U,
    128U,
    "C97445F45CDEF9F0D3E05E1E585FC297235B82B5BE8FF3EFCA67C59852018192",
    "B28EF557BA31DFCBDD21AC46E2A91E3C304F44CB87058ADA2CB815151E610046",
};

constexpr CurveDefinition CURVE_P384{
    CurveId::p384,
    "P-384",
    NID_secp384r1,
    384U,
    368U,
    192U,
    "8E722DE3125BDDB05580164BFE20B8B432216A62926C57502CEEDE31C47816EDD1E89769124179D0B695106428815065",
    "023B1660DD701D0839FD45EEC36F9EE7B32E13B315DC02610AA1B636E346DF671F790F84C5E09B05674DBB7E45C803DD",
};

constexpr CurveDefinition CURVE_P521{
    CurveId::p521,
    "P-521",
    NID_secp521r1,
    521U,
    504U,
    256U,
    "01B9FA3E518D683C6B65763694AC8EFBAEC6FAB44F2276171A42726507DD08ADD4C3B3F4C1EBC5B1222DDBA077F722943B24C3EDFA0F85FE24D0C8C01591F0BE6F63",
    "01F3BDBA585295D9A1110D1DF1F9430EF8442C5018976FF3437EF91B81DC0B8132C8D5C39C32D0E004A3092B7D327C0E7A4D26D2C7B69B58F9066652911E457779DE",
};

[[nodiscard]] const CurveDefinition& curve_for_strength(unsigned requested_strength) {
    require(requested_strength >= 1U && requested_strength <= 256U,
            "requested security strength must be in 1..256");
    if (requested_strength <= CURVE_P256.max_security_strength) {
        return CURVE_P256;
    }
    if (requested_strength <= CURVE_P384.max_security_strength) {
        return CURVE_P384;
    }
    return CURVE_P521;
}

[[nodiscard]] const CurveDefinition& curve_by_id(CurveId id) {
    switch (id) {
        case CurveId::p256:
            return CURVE_P256;
        case CurveId::p384:
            return CURVE_P384;
        case CurveId::p521:
            return CURVE_P521;
    }
    throw Error("unknown curve");
}

class CurveContext {
public:
    explicit CurveContext(const CurveDefinition& definition)
        : definition_(&definition),
          group_(EC_GROUP_new_by_curve_name(definition.nid), EC_GROUP_free),
          p_(nullptr, EC_POINT_free),
          q_(nullptr, EC_POINT_free),
          order_(BN_new(), BN_free) {
        require(group_ != nullptr, "EC_GROUP_new_by_curve_name failed");
        require(order_ != nullptr, "BN_new for order failed");
        auto context = make_bn_ctx();
        require(EC_GROUP_get_order(group_.get(), order_.get(), context.get()) == 1,
                "EC_GROUP_get_order failed");

        p_ = EC_POINT_ptr(EC_POINT_dup(EC_GROUP_get0_generator(group_.get()), group_.get()), EC_POINT_free);
        require(p_ != nullptr, "EC_POINT_dup(generator) failed");

        q_ = make_point(group_.get());
        auto qx = bn_from_hex(definition.qx);
        auto qy = bn_from_hex(definition.qy);
        require(EC_POINT_set_affine_coordinates(group_.get(), q_.get(), qx.get(), qy.get(), context.get()) == 1,
                "official Q point is invalid");
        validate_points();
    }

    CurveContext(const CurveDefinition& definition, const BIGNUM* known_d)
        : CurveContext(definition) {
        auto context = make_bn_ctx();
        require(EC_POINT_mul(group_.get(), q_.get(), nullptr, p_.get(), known_d, context.get()) == 1,
                "constructing lab Q=dP failed");
        validate_points();
    }

    CurveContext(CurveContext&&) noexcept = default;
    CurveContext& operator=(CurveContext&&) noexcept = default;
    CurveContext(const CurveContext&) = delete;
    CurveContext& operator=(const CurveContext&) = delete;

    [[nodiscard]] const CurveDefinition& definition() const noexcept { return *definition_; }
    [[nodiscard]] const EC_GROUP* group() const noexcept { return group_.get(); }
    [[nodiscard]] const EC_POINT* p() const noexcept { return p_.get(); }
    [[nodiscard]] const EC_POINT* q() const noexcept { return q_.get(); }
    [[nodiscard]] const BIGNUM* order() const noexcept { return order_.get(); }

    [[nodiscard]] BN_ptr x_of_scalar_mul(const BIGNUM* scalar, const EC_POINT* point) const {
        auto context = make_bn_ctx();
        auto product = make_point(group_.get());
        require(EC_POINT_mul(group_.get(), product.get(), nullptr, point, scalar, context.get()) == 1,
                "EC_POINT_mul failed");
        require(EC_POINT_is_at_infinity(group_.get(), product.get()) == 0,
                "scalar multiplication reached the point at infinity");
        auto x = make_bn();
        require(EC_POINT_get_affine_coordinates(group_.get(), product.get(), x.get(), nullptr, context.get()) == 1,
                "EC_POINT_get_affine_coordinates failed");
        return x;
    }

private:
    void validate_points() const {
        auto context = make_bn_ctx();
        require(EC_POINT_is_on_curve(group_.get(), p_.get(), context.get()) == 1,
                "P is not on the selected curve");
        require(EC_POINT_is_on_curve(group_.get(), q_.get(), context.get()) == 1,
                "Q is not on the selected curve");

        auto check = make_point(group_.get());
        require(EC_POINT_mul(group_.get(), check.get(), nullptr, q_.get(), order_.get(), context.get()) == 1,
                "nQ multiplication failed");
        require(EC_POINT_is_at_infinity(group_.get(), check.get()) == 1,
                "Q does not have the expected prime-order subgroup membership");
    }

    const CurveDefinition* definition_;
    EC_GROUP_ptr group_;
    EC_POINT_ptr p_;
    EC_POINT_ptr q_;
    BN_ptr order_;
};

class DualEcDrbg {
public:
    static constexpr std::uint64_t reseed_interval = (std::uint64_t{1} << 32U);
    static constexpr std::size_t max_input_bits = (std::size_t{1} << 13U);

    static DualEcDrbg instantiate(
        unsigned requested_security_strength,
        const BitString& entropy_input,
        const BitString& nonce,
        const BitString& personalization_string = BitString{}) {
        const CurveDefinition& definition = curve_for_strength(requested_security_strength);
        return instantiate_with_curve(
            requested_security_strength,
            CurveContext(definition),
            entropy_input,
            nonce,
            personalization_string);
    }

    static DualEcDrbg instantiate_lab(
        unsigned requested_security_strength,
        const BIGNUM* known_d,
        const BitString& entropy_input,
        const BitString& nonce,
        const BitString& personalization_string = BitString{}) {
        const CurveDefinition& definition = curve_for_strength(requested_security_strength);
        return instantiate_with_curve(
            requested_security_strength,
            CurveContext(definition, known_d),
            entropy_input,
            nonce,
            personalization_string);
    }

    DualEcDrbg(DualEcDrbg&&) noexcept = default;
    DualEcDrbg& operator=(DualEcDrbg&&) noexcept = default;
    DualEcDrbg(const DualEcDrbg&) = delete;
    DualEcDrbg& operator=(const DualEcDrbg&) = delete;

    void reseed(const BitString& entropy_input,
                const BitString& additional_input = BitString{}) {
        validate_input_lengths(entropy_input, additional_input);
        require(entropy_input.bit_length() >= security_strength_,
                "reseed entropy input is shorter than the security strength");

        const BitString state_bits = BitString::from_bn(s_.get(), curve_.definition().seedlen);
        const BitString padded_state = state_bits.pad8_right();
        const BitString seed_material = concat({
            std::cref(padded_state),
            std::cref(entropy_input),
            std::cref(additional_input),
        });
        const BitString seed = hash_df(seed_material, curve_.definition().seedlen);
        s_ = seed.to_bn();
        reseed_counter_ = 0U;
    }

    [[nodiscard]] BitString generate(
        std::size_t requested_number_of_bits,
        const std::optional<BitString>& additional_input_string = std::nullopt) {
        require(requested_number_of_bits > 0U, "requested output length must be nonzero");
        if (additional_input_string.has_value()) {
            require(additional_input_string->bit_length() <= max_input_bits,
                    "additional input exceeds 2^13 bits");
        }

        const std::size_t blocks =
            (requested_number_of_bits + curve_.definition().outlen - 1U) / curve_.definition().outlen;
        require(blocks <= reseed_interval, "one request exceeds the NIST reseed interval");
        require(reseed_counter_ <= reseed_interval,
                "reseed required before generating more output");
        require(static_cast<std::uint64_t>(blocks) <= reseed_interval - reseed_counter_,
                "request would cross the NIST reseed interval");

        BitString additional = BitString::zeros(curve_.definition().seedlen);
        if (additional_input_string.has_value()) {
            additional = hash_df(additional_input_string->pad8_right(), curve_.definition().seedlen);
        }
        BN_ptr additional_bn = additional.to_bn();

        BitString temp;
        while (temp.bit_length() < requested_number_of_bits) {
            auto context = make_bn_ctx();
            auto t = make_bn();
            require(BN_mod_add(t.get(), s_.get(), additional_bn.get(), curve_.order(), context.get()) == 1,
                    "BN_mod_add failed");

            s_ = curve_.x_of_scalar_mul(t.get(), curve_.p());
            const BN_ptr r = curve_.x_of_scalar_mul(s_.get(), curve_.q());
            const BitString r_bits = BitString::from_bn(r.get(), curve_.definition().seedlen);
            temp.append(r_bits.right(curve_.definition().outlen));

            BN_zero(additional_bn.get());
            ++reseed_counter_;
        }

        const BitString returned_bits = temp.left(requested_number_of_bits);
        s_ = curve_.x_of_scalar_mul(s_.get(), curve_.p());
        return returned_bits;
    }

    [[nodiscard]] const CurveContext& curve() const noexcept { return curve_; }
    [[nodiscard]] const BIGNUM* state() const noexcept { return s_.get(); }
    [[nodiscard]] unsigned security_strength() const noexcept { return security_strength_; }
    [[nodiscard]] std::uint64_t reseed_counter() const noexcept { return reseed_counter_; }

private:
    DualEcDrbg(unsigned security_strength, CurveContext curve, BN_ptr state)
        : security_strength_(security_strength),
          curve_(std::move(curve)),
          s_(std::move(state)) {}

    static void validate_input_lengths(const BitString& first, const BitString& second) {
        require(first.bit_length() <= max_input_bits, "entropy input exceeds 2^13 bits");
        require(second.bit_length() <= max_input_bits, "input string exceeds 2^13 bits");
        require(first.is_byte_aligned() && second.is_byte_aligned(),
                "external inputs must be byte aligned");
    }

    static DualEcDrbg instantiate_with_curve(
        unsigned requested_security_strength,
        CurveContext curve,
        const BitString& entropy_input,
        const BitString& nonce,
        const BitString& personalization_string) {
        validate_input_lengths(entropy_input, nonce);
        require(personalization_string.bit_length() <= max_input_bits,
                "personalization string exceeds 2^13 bits");
        require(personalization_string.is_byte_aligned(),
                "personalization string must be byte aligned");
        require(entropy_input.bit_length() >= requested_security_strength,
                "entropy input is shorter than the requested security strength");
        require(nonce.bit_length() >= (requested_security_strength + 1U) / 2U,
                "nonce is shorter than half the requested security strength");

        const BitString seed_material = concat({
            std::cref(entropy_input),
            std::cref(nonce),
            std::cref(personalization_string),
        });
        const BitString seed = hash_df(seed_material, curve.definition().seedlen);
        return DualEcDrbg(requested_security_strength, std::move(curve), seed.to_bn());
    }

    unsigned security_strength_;
    CurveContext curve_;
    BN_ptr s_;
    std::uint64_t reseed_counter_ = 0U;
};

[[nodiscard]] BitString deterministic_bytes(std::size_t count, std::uint8_t start) {
    std::vector<std::uint8_t> bytes(count);
    for (std::size_t i = 0; i < count; ++i) {
        bytes[i] = static_cast<std::uint8_t>(start + static_cast<std::uint8_t>(i * 29U));
    }
    return BitString::from_bytes(bytes);
}

[[nodiscard]] std::size_t strength_bytes(unsigned strength) {
    return (strength + 7U) / 8U;
}

void print_official_demo(unsigned strength, std::size_t requested_bits) {
    const BitString entropy = deterministic_bytes(strength_bytes(strength), 0x11U);
    const BitString nonce = deterministic_bytes(strength_bytes((strength + 1U) / 2U), 0xA3U);
    const BitString personalization = BitString::from_ascii("withdrawn-nist-dual-ec-demo");

    DualEcDrbg drbg = DualEcDrbg::instantiate(strength, entropy, nonce, personalization);
    const BitString output = drbg.generate(requested_bits);

    std::cout << "Mode: official NIST SP 800-90A (January 2012) parameters\n";
    std::cout << "Curve: " << drbg.curve().definition().name << "\n";
    std::cout << "Hash_df: SHA-256\n";
    std::cout << "seedlen: " << drbg.curve().definition().seedlen << " bits\n";
    std::cout << "outlen: " << drbg.curve().definition().outlen << " bits\n";
    std::cout << "Output (" << output.bit_length() << " bits): " << output.hex() << "\n";
    std::cout << "Reseed counter: " << drbg.reseed_counter() << " block(s)\n";
}

[[nodiscard]] bool point_equal(const EC_GROUP* group,
                               const EC_POINT* lhs,
                               const EC_POINT* rhs,
                               BN_CTX* context) {
    return EC_POINT_cmp(group, lhs, rhs, context) == 0;
}

void self_test_one(unsigned strength) {
    const BitString entropy = deterministic_bytes(strength_bytes(strength), 0x21U);
    const BitString nonce = deterministic_bytes(strength_bytes((strength + 1U) / 2U), 0x43U);
    const BitString personalization = BitString::from_ascii("self-test");

    DualEcDrbg first = DualEcDrbg::instantiate(strength, entropy, nonce, personalization);
    DualEcDrbg second = DualEcDrbg::instantiate(strength, entropy, nonce, personalization);
    const std::size_t request_bits = first.curve().definition().outlen * 2U + 13U;
    const BitString output_a = first.generate(request_bits, BitString::from_ascii("A"));
    const BitString output_b = second.generate(request_bits, BitString::from_ascii("A"));
    require(output_a == output_b, "deterministic reproducibility test failed");
    require(first.reseed_counter() == 3U, "reseed counter did not count output blocks");

    const BitString reseed_entropy = deterministic_bytes(strength_bytes(strength), 0x77U);
    first.reseed(reseed_entropy, BitString::from_ascii("reseed"));
    require(first.reseed_counter() == 0U, "reseed counter did not reset");
    const BitString after_reseed = first.generate(first.curve().definition().outlen);
    require(!(after_reseed == output_a.left(first.curve().definition().outlen)),
            "reseed did not alter the output stream");

    auto context = make_bn_ctx();
    const EC_POINT* generator = EC_GROUP_get0_generator(first.curve().group());
    require(point_equal(first.curve().group(), first.curve().p(), generator, context.get()),
            "P differs from the NIST curve generator");

    std::cout << "[OK] " << first.curve().definition().name
              << ": official Q valid, deterministic generate, additional input, reseed\n";
}

void run_self_tests() {
    self_test_one(128U);
    self_test_one(192U);
    self_test_one(256U);
    std::cout << "All self-tests passed.\n";
}

struct RecoveryResult {
    bool found = false;
    std::uint16_t missing_prefix = 0U;
    BN_ptr recovered_s2{nullptr, BN_free};
};

[[nodiscard]] std::array<std::uint8_t, 30> block_to_array(const BitString& block) {
    require(block.bit_length() == 240U && block.is_byte_aligned(), "expected a 240-bit block");
    std::array<std::uint8_t, 30> result{};
    const auto& bytes = block.bytes_aligned();
    std::copy(bytes.begin(), bytes.end(), result.begin());
    return result;
}

[[nodiscard]] BitString low_240(const BIGNUM* x) {
    return BitString::from_bn(x, 256U).right(240U);
}

[[nodiscard]] RecoveryResult recover_p256_state_with_trapdoor(
    const CurveContext& curve,
    const BIGNUM* trapdoor_e,
    const BitString& observed_first,
    const BitString& observed_second) {
    require(curve.definition().id == CurveId::p256, "lab recovery is implemented for P-256");
    const auto first = block_to_array(observed_first);
    const auto second = block_to_array(observed_second);

    const unsigned thread_count = std::max(1U, std::thread::hardware_concurrency());
    std::atomic<bool> found{false};
    std::mutex result_mutex;
    RecoveryResult result;
    std::vector<std::thread> workers;
    workers.reserve(thread_count);

    const std::uint32_t total = 1U << 16U;
    const std::uint32_t chunk = (total + thread_count - 1U) / thread_count;

    for (unsigned worker = 0U; worker < thread_count; ++worker) {
        const std::uint32_t begin = worker * chunk;
        const std::uint32_t end = std::min(total, begin + chunk);
        workers.emplace_back([&, begin, end]() {
            if (begin >= end) {
                return;
            }
            auto context = make_bn_ctx();
            auto candidate_point = make_point(curve.group());
            auto e_times_candidate = make_point(curve.group());
            auto output_point = make_point(curve.group());
            auto x_candidate = make_bn();
            auto recovered_s2 = make_bn();
            auto predicted_r2 = make_bn();

            std::array<std::uint8_t, 32> full_x{};
            std::copy(first.begin(), first.end(), full_x.begin() + 2);

            for (std::uint32_t prefix = begin; prefix < end && !found.load(std::memory_order_relaxed); ++prefix) {
                full_x[0] = static_cast<std::uint8_t>((prefix >> 8U) & 0xffU);
                full_x[1] = static_cast<std::uint8_t>(prefix & 0xffU);
                require(BN_bin2bn(full_x.data(), static_cast<int>(full_x.size()), x_candidate.get()) != nullptr,
                        "BN_bin2bn failed in recovery");

                ERR_clear_error();
                if (EC_POINT_set_compressed_coordinates(
                        curve.group(), candidate_point.get(), x_candidate.get(), 0, context.get()) != 1) {
                    ERR_clear_error();
                    continue;
                }

                require(EC_POINT_mul(curve.group(), e_times_candidate.get(), nullptr,
                                     candidate_point.get(), trapdoor_e, context.get()) == 1,
                        "trapdoor point multiplication failed");
                if (EC_POINT_is_at_infinity(curve.group(), e_times_candidate.get()) == 1) {
                    continue;
                }
                require(EC_POINT_get_affine_coordinates(curve.group(), e_times_candidate.get(),
                                                        recovered_s2.get(), nullptr, context.get()) == 1,
                        "extracting recovered state failed");

                require(EC_POINT_mul(curve.group(), output_point.get(), nullptr, curve.q(),
                                     recovered_s2.get(), context.get()) == 1,
                        "validation output multiplication failed");
                require(EC_POINT_get_affine_coordinates(curve.group(), output_point.get(),
                                                        predicted_r2.get(), nullptr, context.get()) == 1,
                        "extracting validation output failed");
                const BitString predicted_block = low_240(predicted_r2.get());
                if (predicted_block.bytes_aligned().size() == second.size() &&
                    std::equal(predicted_block.bytes_aligned().begin(),
                               predicted_block.bytes_aligned().end(), second.begin())) {
                    bool expected = false;
                    if (found.compare_exchange_strong(expected, true)) {
                        std::lock_guard lock(result_mutex);
                        result.found = true;
                        result.missing_prefix = static_cast<std::uint16_t>(prefix);
                        result.recovered_s2 = bn_dup(recovered_s2.get());
                    }
                    return;
                }
            }
        });
    }

    for (auto& worker : workers) {
        worker.join();
    }
    return result;
}

void run_lab_backdoor_demo() {
    // Deliberately known relation Q=dP. This is NOT the official NIST Q; the generator
    // algorithm, truncation direction, state transitions, and output lengths remain the
    // withdrawn SP 800-90A mechanism.
    const BN_ptr d = bn_from_hex("6A1D78C8EAC5D8A74A2F9D33C71B41ED21EEB4A6D73A91C963A6F5E84D70B7B1");
    CurveContext lab_curve(CURVE_P256, d.get());
    auto context = make_bn_ctx();
    BN_ptr e(BN_mod_inverse(nullptr, d.get(), lab_curve.order(), context.get()), BN_free);
    require(e != nullptr, "BN_mod_inverse failed for lab trapdoor");

    const BitString entropy = deterministic_bytes(16U, 0x31U);
    const BitString nonce = deterministic_bytes(8U, 0xB7U);
    DualEcDrbg drbg = DualEcDrbg::instantiate_lab(
        128U, d.get(), entropy, nonce, BitString::from_ascii("known-trapdoor-lab"));
    const BitString stream = drbg.generate(3U * CURVE_P256.outlen);
    const BitString observed_first = stream.slice(0U, 240U);
    const BitString observed_second = stream.slice(240U, 240U);
    const BitString actual_third = stream.slice(480U, 240U);

    const RecoveryResult recovery = recover_p256_state_with_trapdoor(
        drbg.curve(), e.get(), observed_first, observed_second);
    require(recovery.found && recovery.recovered_s2 != nullptr,
            "trapdoor recovery failed");

    const BN_ptr s3 = drbg.curve().x_of_scalar_mul(recovery.recovered_s2.get(), drbg.curve().p());
    const BN_ptr r3 = drbg.curve().x_of_scalar_mul(s3.get(), drbg.curve().q());
    const BitString predicted_third = low_240(r3.get());

    std::cout << "Mode: structural trapdoor laboratory\n";
    std::cout << "Core generator: NIST SP 800-90A (January 2012), P-256, rightmost 240 bits\n";
    std::cout << "Parameter change: Q=dP with known d (not the official NIST Q)\n";
    std::cout << "Observed block 1: " << observed_first.hex() << "\n";
    std::cout << "Observed block 2: " << observed_second.hex() << "\n";
    std::cout << "Recovered missing 16-bit prefix: 0x"
              << std::hex << std::setw(4) << std::setfill('0')
              << recovery.missing_prefix << std::dec << "\n";
    std::cout << "Predicted block 3: " << predicted_third.hex() << "\n";
    std::cout << "Actual block 3:    " << actual_third.hex() << "\n";
    std::cout << "Prediction correct: " << std::boolalpha
              << (predicted_third == actual_third) << "\n";
}

[[nodiscard]] unsigned parse_unsigned(std::string_view text, std::string_view field) {
    std::size_t consumed = 0U;
    unsigned long value = 0U;
    try {
        value = std::stoul(std::string(text), &consumed, 10);
    } catch (const std::exception&) {
        throw Error(std::string(field) + " is not a valid unsigned integer");
    }
    require(consumed == text.size(), std::string(field) + " contains trailing characters");
    require(value <= std::numeric_limits<unsigned>::max(), std::string(field) + " is too large");
    return static_cast<unsigned>(value);
}

void usage(const char* program) {
    std::cout
        << "Usage:\n"
        << "  " << program << " official [security-strength] [output-bits]\n"
        << "  " << program << " self-test\n"
        << "  " << program << " lab-backdoor\n\n"
        << "Examples:\n"
        << "  " << program << " official 128 480\n"
        << "  " << program << " official 256 1008\n"
        << "  " << program << " lab-backdoor\n";
}

}  // namespace dualec

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            dualec::usage(argv[0]);
            return EXIT_FAILURE;
        }

        const std::string_view command(argv[1]);
        if (command == "official") {
            const unsigned strength = argc >= 3 ? dualec::parse_unsigned(argv[2], "security strength") : 128U;
            const std::size_t bits = argc >= 4
                ? static_cast<std::size_t>(dualec::parse_unsigned(argv[3], "output bits"))
                : 480U;
            dualec::print_official_demo(strength, bits);
            return EXIT_SUCCESS;
        }
        if (command == "self-test") {
            dualec::run_self_tests();
            return EXIT_SUCCESS;
        }
        if (command == "lab-backdoor") {
            dualec::run_lab_backdoor_demo();
            return EXIT_SUCCESS;
        }

        dualec::usage(argv[0]);
        return EXIT_FAILURE;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
