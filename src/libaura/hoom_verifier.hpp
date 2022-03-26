#include <math.h>
namespace aura {

    template<class Exponent, class GroupElement>
    HOOMVerifier<Exponent, GroupElement>::HOOMVerifier(const GroupElement &g,
                                                       const std::vector <GroupElement> &h_gens,
                                                       int t_n, int t_m, int m_n, int m_m)
            : g_(g), h_(h_gens), t_n_(t_n), t_m_(t_m), m_n_(m_n), m_m_(m_m) {
    }

    template<class Exponent, class GroupElement>
    bool HOOMVerifier<Exponent, GroupElement>::verify(const std::vector <GroupElement> &commits,
                                                      const HOOMProof <Exponent, GroupElement> &proof) const {
        int t_ = pow(t_n_, t_m_);
        int m_ = pow(m_n_, m_m_);
        aura::SigmaPlusVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> d_verifier(g_, h_, m_n_, m_m_);
        aura::SigmaPlusVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> D_verifier(g_, h_, t_n_, t_m_);

        std::vector <GroupElement> group_elements = {g_, h_[0] * t_n_, h_[0] * t_m_, h_[0] * m_n_, h_[0] * m_m_};
        group_elements.insert(group_elements.end(), proof.d_.begin(), proof.d_.end());
        std::vector <Exponent> x;
        x.resize(m_);
        for (int k = 0; k < m_; ++k) {
//            SigmaPrimitives<Exponent, GroupElement>::generate_challenge(group_elements, x[k]);
            x[k] = uint64_t(124);
            group_elements.push_back(h_[0] * x[k]);
        }
        std::vector <GroupElement> C_;
        C_.resize(m_);
        std::vector <GroupElement> D_;
        D_.resize(t_);
        GroupElement D;
        D = SigmaPrimitives<Exponent, GroupElement>::HelperFunction(proof.d_, x);

        for (int k = 0; k < t_; ++k) {
            std::copy(commits.begin() + k * m_, commits.begin() + (k + 1) * m_, C_.begin());
            D_[k] = D + SigmaPrimitives<Exponent, GroupElement>::HelperFunction(C_, x).inverse();
        }
        if(!d_verifier.verify(proof.d_, proof.d_Proof_, true) && D_verifier.verify(D_, proof.D_Proof_, true)) {
            LogPrintf("Hierarchic one out of many proof failed due to final check failed.");
            return false;
        }
        return true;
    }

} // namespace aura
