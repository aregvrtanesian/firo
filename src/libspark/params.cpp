#include "params.h"
#include "chainparams.h"
#include <iostream>
namespace spark {

    CCriticalSection Params::cs_instance;
    std::unique_ptr<Params> Params::instance;

Params const* Params::get_default() {
    if (instance) {
        return instance.get();
    } else {
        LOCK(cs_instance);
        if (instance) {
            return instance.get();
        }

        // Set the size parameters
        std::size_t n_grootle = 16;
        std::size_t m_grootle = 4;
        std::size_t N_range = 64;
        std::size_t max_M_range = 16;

        // Set the global generators
        std::string F_string = "SPARK_GENERATOR_F";
        std::vector<unsigned char> F_chars(F_string.begin(), F_string.end());
        GroupElement F;
        F.generate(F_chars.data());

        std::string G_string = "SPARK_GENERATOR_G";
        std::vector<unsigned char> G_chars(G_string.begin(), G_string.end());
        GroupElement G;
        G.generate(G_chars.data());

        std::string H_string = "SPARK_GENERATOR_H";
        std::vector<unsigned char> H_chars(H_string.begin(), H_string.end());
        GroupElement H;
        H.generate(H_chars.data());

        std::string U_string = "SPARK_GENERATOR_U";
        std::vector<unsigned char> U_chars(U_string.begin(), U_string.end());
        GroupElement U;
        U.generate(U_chars.data());

        instance.reset(new Params(F, G, H, U, n_grootle, m_grootle, N_range, max_M_range));
        return instance.get();
    }
}

Params::Params(const GroupElement& F_, const GroupElement& G_, const GroupElement& H_, const GroupElement& U_, std::size_t n_grootle_, std::size_t m_grootle_, std::size_t N_range_, std::size_t max_M_range_):
    F(F_),
    G(G_),
    H(H_),
    U(U_),
    n_grootle(n_grootle_),
    m_grootle(m_grootle_),
    N_range(N_range_),
    max_M_range(max_M_range_)
{
    // Range proof generators
    this->G_range.resize(N_range * max_M_range);
    this->H_range.resize(N_range * max_M_range);
    for (std::size_t i = 0; i < N_range * max_M_range; i++) {
        std::string G_range_string = "SPARK_GENERATOR_G_RANGE:" + std::to_string(i);
        std::vector<unsigned char> G_range_chars(G_range_string.begin(), G_range_string.end());
        this->G_range[i].generate(G_range_chars.data());

        std::string H_range_string = "SPARK_GENERATOR_H_RANGE:" + std::to_string(i);
        std::vector<unsigned char> H_range_chars(H_range_string.begin(), H_range_string.end());
        this->H_range[i].generate(H_range_chars.data());
    }

    // One-of-many proof generators
    this->G_grootle.resize(n_grootle * m_grootle);
    for (std::size_t i = 0; i < n_grootle * m_grootle; i++) {
        std::string G_grootle_string = "SPARK_GENERATOR_G_GROOTLE:" + std::to_string(i);
        std::vector<unsigned char> G_grootle_chars(G_grootle_string.begin(), G_grootle_string.end());
        this->G_grootle[i].generate(G_grootle_chars.data());
    }
}

const GroupElement& Params::get_F() const {
    return F;
}

const GroupElement& Params::get_G() const {
    return G;
}

const GroupElement& Params::get_H() const {
    return H;
}

const GroupElement& Params::get_U() const {
    return U;
}

const std::vector<GroupElement>& Params::get_G_range() const {
    return G_range;
}

const std::vector<GroupElement>& Params::get_H_range() const {
    return H_range;
}

const std::vector<GroupElement>& Params::get_G_grootle() const {
    return G_grootle;
}

std::size_t Params::get_N_range() const {
    return N_range;
}

std::size_t Params::get_max_M_range() const {
    return max_M_range;
}

std::size_t Params::get_n_grootle() const {
    return n_grootle;
}

std::size_t Params::get_m_grootle() const {
    return m_grootle;
}

}
