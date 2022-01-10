#include "params.h"
#include "chainparams.h"
#include "util.h"

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
        GroupElement F = SparkUtils::hash_generator(LABEL_GENERATOR_F);
        GroupElement G = SparkUtils::hash_generator(LABEL_GENERATOR_G);
        GroupElement H = SparkUtils::hash_generator(LABEL_GENERATOR_H);
        GroupElement U = SparkUtils::hash_generator(LABEL_GENERATOR_U);

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
        this->G_range[i] = SparkUtils::hash_generator(LABEL_GENERATOR_G_RANGE + " " + std::to_string(i));
        this->H_range[i] = SparkUtils::hash_generator(LABEL_GENERATOR_H_RANGE + " " + std::to_string(i));
    }

    // One-of-many proof generators
    this->G_grootle.resize(n_grootle * m_grootle);
    for (std::size_t i = 0; i < n_grootle * m_grootle; i++) {
        this->G_grootle[i] = SparkUtils::hash_generator(LABEL_GENERATOR_G_GROOTLE + " " + std::to_string(i));
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
