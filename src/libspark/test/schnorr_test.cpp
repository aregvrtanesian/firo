#include "../schnorr.h"
#include "../../streams.h"
#include "../../version.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_schnorr_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(serialization)
{
    std::size_t n = 3;

    std::vector<GroupElement> G;
    std::vector<Scalar> y;
    G.resize(n);
    y.resize(n);
    GroupElement Y;
    for (std::size_t i = 0; i < n; i++) {
        G[i].randomize();
        y[i].randomize();
        Y += G[i]*y[i];
    }

    SchnorrProof proof;

    Schnorr schnorr(G);
    schnorr.prove(y, Y, proof);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof;

    SchnorrProof deserialized;
    serialized >> deserialized;

    BOOST_CHECK(proof.A == deserialized.A);
    for (std::size_t i = 0; i < n; i++) {
        BOOST_CHECK(proof.t[i] == deserialized.t[i]);
    }
}

BOOST_AUTO_TEST_CASE(completeness)
{
    std::size_t n = 3;

    std::vector<GroupElement> G;
    std::vector<Scalar> y;
    G.resize(n);
    y.resize(n);
    GroupElement Y;
    for (std::size_t i = 0; i < n; i++) {
        G[i].randomize();
        y[i].randomize();
        Y += G[i]*y[i];
    }

    SchnorrProof proof;

    Schnorr schnorr(G);
    schnorr.prove(y, Y, proof);

    BOOST_CHECK(schnorr.verify(Y, proof));
}

BOOST_AUTO_TEST_CASE(bad_proofs)
{
    std::size_t n = 3;

    std::vector<GroupElement> G;
    std::vector<Scalar> y;
    G.resize(n);
    y.resize(n);
    GroupElement Y;
    for (std::size_t i = 0; i < n; i++) {
        G[i].randomize();
        y[i].randomize();
        Y += G[i]*y[i];
    }

    SchnorrProof proof;

    Schnorr schnorr(G);
    schnorr.prove(y, Y, proof);
    
    // Bad Y
    GroupElement evil_Y;
    evil_Y.randomize();
    BOOST_CHECK(!(schnorr.verify(evil_Y, proof)));

    // Bad A
    SchnorrProof evil_proof = proof;
    evil_proof.A.randomize();
    BOOST_CHECK(!(schnorr.verify(Y, evil_proof)));

    // Bad t
    for (std::size_t i = 0; i < n; i++) {
        evil_proof = proof;
        evil_proof.t[i].randomize();
        BOOST_CHECK(!(schnorr.verify(Y, evil_proof)));
    }
}

BOOST_AUTO_TEST_SUITE_END()

}
