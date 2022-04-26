#include <math.h>
#include <iostream>

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
        Exponent y;
        SigmaPrimitives<Exponent, GroupElement>::generate_challenge(commits, y);
        int t_ = pow(t_n_, t_m_);
        int m_ = pow(m_n_, m_m_);
        aura::SigmaPlusVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> d_verifier(g_, h_, m_n_, m_m_);
        aura::SigmaPlusVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> D_verifier(g_, h_, t_n_, t_m_);

        if(!d_verifier.verify(proof.d_, proof.d_Proof_, true, y)) {
            LogPrintf("Hierarchic one out of many proof failed due to d_ check failed.");
            return false;
        }
        std::vector<Scalar> x;
        x.resize(m_);
        SigmaPrimitives<Exponent, GroupElement>::generate_challenge({h_[0] * y}, x[0]);
        for (int k = 1; k < m_; ++k) {
            SigmaPrimitives<Exponent, GroupElement>::generate_challenge({h_[0] * x[k - 1]}, x[k]);
        }
        std::vector <GroupElement> D_;
        D_.resize(t_);
        GroupElement D;
        D = SigmaPrimitives<Exponent, GroupElement>::HelperFunction(proof.d_, x);

        for (int k = 0; k < t_; ++k) {
            D_[k] = D + SigmaPrimitives<Exponent, GroupElement>::HelperFunction({commits.begin() + k * m_, commits.begin() + (k + 1) * m_}, x).inverse();
        }
        if(!D_verifier.verify(D_, proof.D_Proof_, true, x[m_ - 1])) {
            LogPrintf("Hierarchic one out of many proof failed due to D_ check failed.");
            return false;
        }
        return true;
    }

    template<class Exponent, class GroupElement>
    bool HOOMVerifier<Exponent, GroupElement>::batch_verify(const std::vector<GroupElement>& commits,
                                                      const std::vector<Exponent>& serials,
                                                      const std::vector<HOOMProof<Exponent, GroupElement>>& proofs)  const {
        Exponent commits_hash;
        SigmaPrimitives<Exponent, GroupElement>::generate_challenge(commits, commits_hash);
        int t_ = pow(t_n_, t_m_);
        int m_ = pow(m_n_, m_m_);
        int batchsize = serials.size();
        std::vector <GroupElement> D_;
        D_.resize(t_);
        GroupElement D;
        GroupElement left;
        GroupElement right;
        GroupElement t;
        std::vector<Exponent> f_i_;
        GroupElement zero_commit;
        aura::SigmaPlusVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> d_verifier(g_, h_, m_n_, m_m_);
        aura::SigmaPlusVerifier<secp_primitives::Scalar, secp_primitives::GroupElement> D_verifier(g_, h_, t_n_, t_m_);
        std::vector<Exponent> x;
        x.resize(m_);
        std::vector<Exponent> pows;
        pows.resize(commits.size());

        for(int i = 0; i < batchsize; ++i){
            Exponent y = commits_hash;
            if(!d_verifier.verify(proofs[i].d_, proofs[i].d_Proof_, true, y)){
                LogPrintf("Hierarchic one out of many proof failed due to d_ check failed.");
                return false;
            }
            SigmaPrimitives<Exponent, GroupElement>::generate_challenge({h_[0] * y}, x[0]);
            for (int k = 1; k < m_; ++k) {
                SigmaPrimitives<Exponent, GroupElement>::generate_challenge({h_[0] * x[k - 1]}, x[k]);
            }
            D = SigmaPrimitives<Exponent, GroupElement>::HelperFunction(proofs[i].d_, x);
            for (int k = 0; k < t_; ++k) {
                D_[k] = D + SigmaPrimitives<Exponent, GroupElement>::HelperFunction({commits.begin() + k * m_, commits.begin() + (k + 1) * m_}, x).inverse();
            }
            Exponent xtemp = x[m_ - 1];
            if(!D_verifier.calculate_batch(D_, proofs[i].D_Proof_, t, f_i_, zero_commit, xtemp)){
                LogPrintf("Hierarchic one out of many proof failed due to one of D_ checks failed.");
                return false;
            }
            Exponent f_i_sum;
            for(int k = 0; k < t_; ++k){
                for(int j = 0; j < m_; ++j) {
                    pows[k * m_ + j] += x[j] * f_i_[k] * serials[i];
                }
                f_i_sum += f_i_[k];
            }
            left += t * serials[i] + D * f_i_sum * serials[i];
            right += zero_commit * serials[i];
        }
        secp_primitives::MultiExponent mult(commits, pows);
        right += mult.get_multiple();
        if(left != right) {
            LogPrintf("Hierarchic one out of many proof failed due to final batch check failed.");
            return false;
        }
        return true;
    }

} // namespace aura
