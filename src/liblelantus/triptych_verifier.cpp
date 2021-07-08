#include "triptych_verifier.h"
#include "util.h"

namespace lelantus {

TriptychVerifier::TriptychVerifier(
        const GroupElement& g,
        const std::vector<GroupElement>& h_gens,
        const GroupElement& u,
        std::size_t n,
        std::size_t m)
        : g_(g)
        , h_(h_gens)
        , u_(u)
        , n(n)
        , m(m){
}

// Verify a single one-of-many proof
// In this case, there is an implied input set size
bool TriptychVerifier::singleverify(
        const std::vector<GroupElement>& commits,
        const std::vector<GroupElement>& amount_commits,
        const Scalar& input_hash,
        const GroupElement& offset,
        const TriptychProof& proof) const {
    std::vector<GroupElement> offsets = { offset };
    std::vector<std::size_t> setSizes = { };
    std::vector<TriptychProof> proofs = { proof };

    return verify(
        commits,
        amount_commits,
        input_hash,
        offsets,
        setSizes,
        false,
        proofs
    );
}

// Verify a single one-of-many proof
// In this case, there is a specified set size
bool TriptychVerifier::singleverify(
        const std::vector<GroupElement>& commits,
        const std::vector<GroupElement>& amount_commits,
        const Scalar& input_hash,
        const GroupElement& offset,
        const size_t setSize,
        const TriptychProof& proof) const {
    std::vector<GroupElement> offsets = { offset };
    std::vector<std::size_t> setSizes = { setSize };
    std::vector<TriptychProof> proofs = { proof };

    return verify(
        commits,
        amount_commits,
        input_hash,
        offsets,
        setSizes,
        true,
        proofs
    );
}

// Verify a batch of one-of-many proofs from the same transaction
// In this case, there is an implied input set size
bool TriptychVerifier::batchverify(
        const std::vector<GroupElement>& commits,
        const std::vector<GroupElement>& amount_commits,
        const Scalar& input_hash,
        const std::vector<GroupElement>& offsets,
        const std::vector<TriptychProof>& proofs) const {
    std::vector<std::size_t> setSizes = { };

    return verify(
        commits,
        amount_commits,
        input_hash,
        offsets,
        setSizes,
        false,
        proofs
    );
}

// Verify a general batch of one-of-many proofs
// In this case, each proof has a specified set size
bool TriptychVerifier::batchverify(
        const std::vector<GroupElement>& commits,
        const std::vector<GroupElement>& amount_commits,
        const Scalar& input_hash,
        const std::vector<GroupElement>& offsets,
        const std::vector<size_t>& setSizes,
        const std::vector<TriptychProof>& proofs) const {

    return verify(
        commits,
        amount_commits,
        input_hash,
        offsets,
        setSizes,
        true,
        proofs
    );
}

// Verify a batch of one-of-many proofs
bool TriptychVerifier::verify(
        const std::vector<GroupElement>& commits,
        const std::vector<GroupElement>& amount_commits,
        const Scalar& input_hash,
        const std::vector<GroupElement>& offsets,
        const std::vector<size_t>& setSizes,
        const bool specifiedSetSizes,
        const std::vector<TriptychProof>& proofs) const {
    // Sanity checks
    if (n < 2 || m < 2) {
        LogPrintf("Verifier parameters are invalid");
        return false;
    }
    std::size_t M = proofs.size();
    std::size_t N = (std::size_t)pow(n, m);

    if (commits.size() == 0) {
        LogPrintf("Cannot have empty commitment set");
        return false;
    }
    if (amount_commits.size() != commits.size()) {
        LogPrintf("Amount commitment seet size is invalid");
    }
    if (commits.size() > N) {
        LogPrintf("Commitment set is too large");
        return false;
    }
    if (h_.size() != n * m) {
        LogPrintf("Generator vector size is invalid");
        return false;
    }
    if (offsets.size() != M) {
        LogPrintf("Invalid number of offsets provided");
        return false;
    }

    // If we have specified set sizes, we must have enough
    if (specifiedSetSizes && setSizes.size() != M) {
        LogPrintf("Invalid set size vector size");
        return false;
    }

    // All proof elements must be valid
    for (std::size_t t = 0; t < M; ++t) {
        if (!membership_checks(proofs[t])) {
            LogPrintf("Invalid membership check");  
            return false;
        }
    }

    // Final batch multiscalar multiplication
    Scalar g_scalar = Scalar(uint64_t(0)); // associated to g_
    Scalar u_scalar = Scalar(uint64_t(0)); // associated to u_
    std::vector<Scalar> h_scalars; // associated to (h_)
    std::vector<Scalar> commit_scalars; // associated to commitment list
    std::vector<Scalar> amount_commit_scalars; // associated to commitment list
    h_scalars.reserve(n * m);
    h_scalars.resize(n * m);
    for (size_t i = 0; i < n * m; i++) {
        h_scalars[i] = Scalar(uint64_t(0));
    }
    commit_scalars.reserve(commits.size());
    commit_scalars.resize(commits.size());
    amount_commit_scalars.reserve(amount_commits.size());
    amount_commit_scalars.resize(amount_commits.size());
    for (size_t i = 0; i < commits.size(); i++) {
        commit_scalars[i] = Scalar(uint64_t(0));
        amount_commit_scalars[i] = Scalar(uint64_t(0));
    }

    // Set up the final batch elements
    std::vector<GroupElement> points;
    std::vector<Scalar> scalars;
    std::size_t final_size = 2 + m * n + commits.size() + amount_commits.size(); // g, u, (h_), (commits), (amounts)
    for (std::size_t t = 0; t < M; t++) {
        final_size += 7 + proofs[t].X_.size() + proofs[t].Y_.size(); // A, B, C, D, (X), (Y), offset, J, K
    }
    points.reserve(final_size);
    scalars.reserve(final_size);

    // Index decomposition, which is common among all proofs
    std::vector<std::vector<std::size_t> > I_;
    I_.reserve(commits.size());
    I_.resize(commits.size());
    for (std::size_t i = 0; i < commits.size(); i++) {
        I_[i] = LelantusPrimitives::convert_to_nal(i, n, m);
    }

    // Process all proofs
    for (std::size_t t = 0; t < M; t++) {
        TriptychProof proof = proofs[t];

        // Challenges
        Scalar mu;
        Scalar x;
        LelantusPrimitives::generate_triptych_mu(proof, input_hash, offsets[t], mu);
        LelantusPrimitives::generate_triptych_x(proof, mu, x);

        // Generate random verifier weights
        Scalar w1, w2, w3, w4;
        w1.randomize();
        w2.randomize();
        w3.randomize();
        w4.randomize();

        // Reconstruct f-matrix
        std::vector<Scalar> f_;
        if (!compute_fs(proof, x, f_)) {
            LogPrintf("Invalid matrix reconstruction");
            return false;
        }

        // Effective set size
        std::size_t setSize;
        if (!specifiedSetSizes) {
            setSize = commits.size();
        }
        else {
            setSize = setSizes[t];
        }

        // A, B, C, D (and associated commitments)
        points.emplace_back(proof.A_);
        scalars.emplace_back(w1.negate());
        points.emplace_back(proof.B_);
        scalars.emplace_back(x.negate() * w1);
        points.emplace_back(proof.C_);
        scalars.emplace_back(x.negate() * w2);
        points.emplace_back(proof.D_);
        scalars.emplace_back(w2.negate());

        g_scalar += proof.zA_ * w1 + proof.zC_ * w2;
        for (std::size_t i = 0; i < m * n; i++) {
            h_scalars[i] += f_[i] * (w1 + (x - f_[i]) * w2);
        }

        // Input sets and associated values
        Scalar f_sum(uint64_t(0)); // sum across all indices

        Scalar f_i(uint64_t(1));
        std::vector<Scalar>::iterator ptr_commit;
        std::vector<Scalar>::iterator ptr_amount_commit;
        if (!specifiedSetSizes) {
            ptr_commit = commit_scalars.begin();
            ptr_amount_commit = amount_commit_scalars.begin();
        }
        else {
            ptr_commit = commit_scalars.begin() + commits.size() - setSize;
            ptr_amount_commit = amount_commit_scalars.begin() + amount_commits.size() - setSize;
        }
        compute_batch_fis(f_sum, f_i, m, f_, w3, mu, ptr_commit, ptr_amount_commit, ptr_commit, ptr_commit + setSize - 1);

        Scalar pow(uint64_t(1));
        std::vector<Scalar> f_part_product;
        for (std::size_t j = m; j > 0; j--) {
            f_part_product.push_back(pow);
            pow *= f_[(j - 1) * n + I_[setSize - 1][j - 1]];
        }

        NthPower xj(x);
        for (std::size_t j = 0; j < m; j++) {
            Scalar fi_sum(uint64_t(0));
            for (std::size_t i = I_[setSize - 1][j] + 1; i < n; i++)
                fi_sum += f_[j*n + i];
            pow += fi_sum * xj.pow * f_part_product[m - j - 1];
            xj.go_next();
        }

        f_sum += pow;
        commit_scalars[commits.size() - 1] += pow * w3;
        amount_commit_scalars[amount_commit_scalars.size() - 1] += mu * pow * w3;

        // offset
        points.emplace_back(offsets[t]);
        scalars.emplace_back(mu * f_sum * w3.negate());

        // (X), (Y)
        NthPower x_k(x);
        for (std::size_t k = 0; k < m; k++) {
            points.emplace_back(proof.X_[k]);
            scalars.emplace_back(x_k.pow.negate() * w3);
            points.emplace_back(proof.Y_[k]);
            scalars.emplace_back(x_k.pow.negate() * w4);
            x_k.go_next();
        }

        // J, K, u_, g_
        points.emplace_back(proof.J_);
        scalars.emplace_back(proof.z_ * w4.negate());
        points.emplace_back(proof.K_);
        scalars.emplace_back(mu * f_sum * w4);

        u_scalar += f_sum * w4;
        g_scalar += proof.z_ * w3.negate();
    }

    // Add common generators
    points.emplace_back(g_);
    scalars.emplace_back(g_scalar);
    points.emplace_back(u_);
    scalars.emplace_back(u_scalar);
    for (std::size_t i = 0; i < m * n; i++) {
        points.emplace_back(h_[i]);
        scalars.emplace_back(h_scalars[i]);
    }
    for (std::size_t i = 0; i < commits.size(); i++) {
        points.emplace_back(commits[i]);
        scalars.emplace_back(commit_scalars[i]);
        points.emplace_back(amount_commits[i]);
        scalars.emplace_back(amount_commit_scalars[i]);
    }

    // Verify the batch
    if (points.size() != final_size || scalars.size() != final_size) {
        LogPrintf("Unexpected final size!");
        return false;
    }
    secp_primitives::MultiExponent result(points, scalars);
    if (result.get_multiple().isInfinity()) {
        return true;
    }
    return false;
}

bool TriptychVerifier::membership_checks(const TriptychProof& proof) const {
    if (!(proof.A_.isMember() &&
         proof.B_.isMember() &&
         proof.C_.isMember() &&
         proof.D_.isMember() &&
         proof.J_.isMember() &&
         proof.K_.isMember()) ||
        (proof.A_.isInfinity() ||
         proof.B_.isInfinity() ||
         proof.C_.isInfinity() ||
         proof.D_.isInfinity() ||
         proof.J_.isInfinity() ||
         proof.K_.isInfinity()))
        return false;

    for (std::size_t i = 0; i < proof.f_.size(); i++)
    {
        if (!proof.f_[i].isMember() || proof.f_[i].isZero())
            return false;
    }
    const std::vector <GroupElement>& X_ = proof.X_;
    const std::vector <GroupElement>& Y_ = proof.Y_;
    for (std::size_t k = 0; k < m; ++k)
    {
        if (!(X_[k].isMember() && Y_[k].isMember())
           || X_[k].isInfinity() || Y_[k].isInfinity())
            return false;
    }
    if(!(proof.zA_.isMember() &&
         proof.zC_.isMember() &&
         proof.z_.isMember()) ||
        (proof.zA_.isZero() ||
         proof.zC_.isZero() ||
         proof.z_.isZero()))
        return false;
    return true;
}

bool TriptychVerifier::compute_fs(
        const TriptychProof& proof,
        const Scalar& x,
        std::vector<Scalar>& f_) const {
    for (std::size_t j = 0; j < proof.f_.size(); ++j) {
        if(proof.f_[j] == x)
            return false;
    }

    f_.reserve(n * m);
    for (std::size_t j = 0; j < m; ++j)
    {
        f_.push_back(Scalar(uint64_t(0)));
        Scalar temp;
        std::size_t k = n - 1;
        for (std::size_t i = 0; i < k; ++i)
        {
            temp += proof.f_[j * k + i];
            f_.emplace_back(proof.f_[j * k + i]);
        }
        f_[j * n] = x - temp;
    }
    return true;
}

void TriptychVerifier::compute_batch_fis(
        Scalar& f_sum,
        const Scalar& f_i,
        int j,
        const std::vector<Scalar>& f,
        const Scalar& w3,
        const Scalar& mu,
        std::vector<Scalar>::iterator& ptr_commit,
        std::vector<Scalar>::iterator& ptr_amount_commit,
        std::vector<Scalar>::iterator start_ptr,
        std::vector<Scalar>::iterator end_ptr) const {
    j--;
    if (j == -1)
    {
        if(ptr_commit >= start_ptr && ptr_commit < end_ptr){
            *ptr_commit++ += f_i * w3;
            *ptr_amount_commit++ += mu * f_i * w3;
            f_sum += f_i;
        }
        return;
    }

    Scalar t;

    for (int i = 0; i < n; i++)
    {
        t = f[j * n + i];
        t *= f_i;

        compute_batch_fis(f_sum, t, j, f, w3, mu, ptr_commit, ptr_amount_commit, start_ptr, end_ptr);
    }
}

} //namespace lelantus