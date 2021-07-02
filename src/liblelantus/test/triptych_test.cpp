#include "../triptych_prover.h"
#include "../triptych_verifier.h"
#include "../challenge_generator_impl.h"

#include "lelantus_test_fixture.h"

#include <boost/test/unit_test.hpp>

namespace lelantus {

class TriptychTests : public LelantusTestingSetup {
public:
    struct Secret {
    public:
        Secret(std::size_t l) : l(l) {
            r.randomize();
            s.randomize();
            s1.randomize();
        }

    public:
        std::size_t l;
        Scalar r; // commitment key
        Scalar s; // amount key
        Scalar s1; // offset key
    };

public:
    typedef TriptychProver Prover;
    typedef TriptychProof Proof;
    typedef TriptychVerifier Verifier;

public:
    TriptychTests() {}

public:
    void GenerateParams(std::size_t _N, std::size_t _n, std::size_t _m = 0) {
        N = _N;
        n = _n;
        m = _m;
        if (!m) {
            if (n <= 1) {
                throw std::logic_error("Try to get value of m from invalid n");
            }

            m = (std::size_t)std::round(log(N) / log(n));
        }

        // Public generators
        h_gens = RandomizeGroupElements(n * m);
        g.randomize();
        u.randomize();
    }

    Scalar hash(std::vector<GroupElement> commits, std::vector<GroupElement> amount_commits) {
        std::unique_ptr<ChallengeGenerator> challengeGenerator;
        challengeGenerator = std::make_unique<ChallengeGeneratorImpl<CHash256>>(1);
        challengeGenerator->add(commits);
        challengeGenerator->add(amount_commits);

        Scalar result_out;
        challengeGenerator->get_challenge(result_out);
        return result_out;
    }

public:
    std::size_t N;
    std::size_t n;
    std::size_t m;

    std::vector<GroupElement> h_gens;
    GroupElement g;
    GroupElement u;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_triptych_tests, TriptychTests)

BOOST_AUTO_TEST_CASE(one_out_of_N)
{
    GenerateParams(8, 2);
    std::size_t index = 0;

    Secret secret(index);
    Prover prover(g, h_gens, u, n, m);
    Verifier verifier(g, h_gens, u, n, m);

    auto commits = RandomizeGroupElements(N);
    auto amount_commits = RandomizeGroupElements(N);
    Scalar input_hash = hash(commits, amount_commits);

    commits[index] = g * secret.r;
    amount_commits[index] = g * secret.s;

    Scalar offset_scalar;
    offset_scalar.randomize();
    GroupElement offset = g * offset_scalar;

    Proof proof;
    prover.triptych_prove(
        commits,
        amount_commits,
        input_hash,
        offset,
        index,
        secret.r,
        secret.s - offset_scalar,
        proof
    );
    BOOST_CHECK(verifier.singleverify(
        commits,
        amount_commits,
        input_hash,
        offset,
        proof
    ));
}

BOOST_AUTO_TEST_CASE(one_out_of_N_variable_batch)
{
    GenerateParams(64, 4);

    std::size_t commit_size = 60; // require padding
    auto commits = RandomizeGroupElements(commit_size);
    auto amount_commits = RandomizeGroupElements(commit_size);
    Scalar input_hash = hash(commits, amount_commits);

    // Generate
    std::vector<Secret> secrets;
    std::vector<std::size_t> indexes = { 0, 1, 3, 59 };
    std::vector<std::size_t> set_sizes = { 60, 60, 59, 16 };
    
    for (auto index : indexes) {
        secrets.emplace_back(Secret(index));

        auto &s = secrets.back();

        // Set the known commitments
        commits[index] = g * s.r;
        amount_commits[index] = g * s.s;
    }

    Prover prover(g, h_gens, u, n, m);
    Verifier verifier(g, h_gens, u, n, m);
    std::vector<Proof> proofs;
    std::vector<GroupElement> offsets;

    for (std::size_t i = 0; i < secrets.size(); i++) {
        proofs.emplace_back();
        offsets.emplace_back(g * secrets[i].s1);
        std::vector<GroupElement> commits_(commits.begin() + commit_size - set_sizes[i], commits.end());
        std::vector<GroupElement> amount_commits_(amount_commits.begin() + commit_size - set_sizes[i], amount_commits.end());

        // Generate proof
        prover.triptych_prove(
            commits_,
            amount_commits_,
            input_hash,
            offsets[i],
            secrets[i].l - (commit_size - set_sizes[i]),
            secrets[i].r,
            secrets[i].s - secrets[i].s1,
            proofs[i]
        );

        // Verify individual proofs as a sanity check
        BOOST_CHECK(verifier.singleverify(
            commits,
            amount_commits,
            input_hash,
            offsets[i],
            set_sizes[i],
            proofs[i]
        ));
        BOOST_CHECK(verifier.singleverify(
            commits_,
            amount_commits_,
            input_hash,
            offsets[i],
            proofs[i]
        ));
    }

    BOOST_CHECK(verifier.batchverify(
        commits,
        amount_commits,
        input_hash,
        offsets,
        set_sizes,
        proofs
    ));
}

BOOST_AUTO_TEST_CASE(one_out_of_N_batch)
{
    GenerateParams(16, 4);

    auto commits = RandomizeGroupElements(N);
    auto amount_commits = RandomizeGroupElements(N);
    Scalar input_hash = hash(commits, amount_commits);

    // Generate
    std::vector<Secret> secrets;

    for (auto index : {1, 3, 5, 9, 15}) {
        secrets.emplace_back(Secret(index));

        auto &s = secrets.back();

        // Set the known commitments
        commits[index] = g * s.r;
        amount_commits[index] = g * s.s;
    }

    Prover prover(g, h_gens, u, n, m);
    Verifier verifier(g, h_gens, u, n, m);
    std::vector<Proof> proofs;
    std::vector<GroupElement> offsets;

    for (std::size_t i = 0; i < secrets.size(); i++) {
        proofs.emplace_back();
        offsets.push_back(g * secrets[i].s1);

        // Generate proof
        prover.triptych_prove(
            commits,
            amount_commits,
            input_hash,
            offsets[i],
            secrets[i].l,
            secrets[i].r,
            secrets[i].s - secrets[i].s1,
            proofs[i]
        );

        // Verify individual proofs as a sanity check
        BOOST_CHECK(verifier.singleverify(
            commits,
            amount_commits,
            input_hash,
            offsets[i],
            proofs[i]
        ));
    }

    BOOST_CHECK(verifier.batchverify(
        commits,
        amount_commits,
        input_hash,
        offsets,
        proofs
    ));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus