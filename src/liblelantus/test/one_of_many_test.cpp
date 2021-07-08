#include "../sigmaextended_prover.h"
#include "../sigmaextended_verifier.h"

#include "lelantus_test_fixture.h"
#include "../challenge_generator_impl.h"

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <random>

namespace lelantus {

class OneOfManyTests : public LelantusTestingSetup {
public:
    OneOfManyTests() {}

public:
    void GenerateParams(uint64_t _N, uint64_t _n, uint64_t _m) {
        N = _N;
        n = _n;
        m = _m;
        if (!((uint64_t)pow(_n, _m) == N)) {
            throw std::invalid_argument("Invalid one-of-many proof parameters");
        }

        // For the one-of-many prover and verifier, we need to ensure the generator vectors begin with the commitment generators
        h_gens = RandomizeGroupElements(n * m);
        g.randomize();
        h1.randomize();
        h2.randomize();
        h_gens[1] = h1;
        h_gens[0] = h2;
    }

public:
    uint64_t N;
    uint64_t n;
    uint64_t m;

    std::vector<GroupElement> h_gens;
    GroupElement g, h1, h2;
};

BOOST_FIXTURE_TEST_SUITE(lelantus_one_of_many_tests, OneOfManyTests)

BOOST_AUTO_TEST_CASE(generate_proofs)
{
    GenerateParams(32, 2, 5);

    auto commits = RandomizeGroupElements(N);
    SigmaExtendedProver prover(
        g, h_gens, n, m
    );
    SigmaExtendedVerifier verifier(
        g, h_gens, n, m
    );

    // For timing data
    std::default_random_engine randomizer;
    std::uniform_int_distribution<int> dist(0,N-1);
    const int trials = 1000;
    double prove_total = 0;
    double verify_total = 0;

    for (int i = 0; i < trials; i++) {
        Scalar v, r;
        v.randomize();
        r.randomize();

        int l = dist(randomizer);

        commits[l] = Primitives::double_commit(
            g, Scalar(uint64_t(0)),
            h1, v,
            h2, r
        );

        // Prove
        auto start = std::chrono::steady_clock::now();

        std::unique_ptr<ChallengeGenerator> transcript = std::make_unique<ChallengeGeneratorImpl<CHash256>>(1); 
        std::string domain("One-of-many proof");
        std::vector<unsigned char> initialize(domain.begin(), domain.end());
        transcript->add(initialize);
        transcript->add(commits);

        // Prover state
        Scalar rA, rB, rC, rD;
        rA.randomize();
        rB.randomize();
        rC.randomize();
        rD.randomize();
        std::vector<Scalar> a, sigma;
        a.reserve(n * m);
        a.resize(n * m);
        std::vector<Scalar> Tk, Pk, Yk;
        Tk.reserve(m);
        Tk.resize(m);
        Pk.reserve(m);
        Pk.resize(m);
        Yk.reserve(m);
        Yk.resize(m);


        SigmaExtendedProof proof;
        prover.sigma_commit(
            commits,
            l,
            rA, rB, rC, rD,
            a, Tk, Pk, Yk,
            sigma,
            proof
        );

        // Update transcript
        transcript->add(proof.A_);
        transcript->add(proof.B_);
        transcript->add(proof.C_);
        transcript->add(proof.D_);
        transcript->add(proof.Gk_);
        transcript->add(proof.Qk);

        // Challenge
        Scalar challenge;
        transcript->get_challenge(challenge);

        // Final proof
        prover.sigma_response(
            sigma, a,
            rA, rB, rC, rD,
            v, r,
            Tk, Pk,
            challenge,
            proof
        );

        auto stop = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::milli> duration_milliseconds = stop - start;
        prove_total += duration_milliseconds.count();

        // Verify
        start = std::chrono::steady_clock::now();

        std::vector<SigmaExtendedProof> proofs;
        proofs.reserve(1);
        proofs.resize(1);
        proofs[0] = proof;

        std::vector<Scalar> serials;
        serials.reserve(1);
        serials.resize(1);
        serials[0] = Scalar(uint64_t(0));

        transcript = std::make_unique<ChallengeGeneratorImpl<CHash256>>(1); 
        transcript->add(initialize);
        transcript->add(commits);
        transcript->add(proof.A_);
        transcript->add(proof.B_);
        transcript->add(proof.C_);
        transcript->add(proof.D_);
        transcript->add(proof.Gk_);
        transcript->add(proof.Qk);

        verifier.batchverify(
            commits,
            challenge,
            serials,
            proofs
        );
        stop = std::chrono::steady_clock::now();
        duration_milliseconds = stop - start;
        verify_total += duration_milliseconds.count();
    }

    // Report the mean time
    printf("Mean proving time (%d trials): %f ms\n", trials, prove_total/trials);
    printf("Mean verification time (%d trials): %f ms\n", trials, verify_total/trials);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace lelantus