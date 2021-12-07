#include "../schnorr.h"
#include "../../streams.h"
#include "../../version.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_schnorr_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(serialization)
{
    GroupElement G;
    G.randomize();

    Scalar y;
    y.randomize();
    GroupElement Y = G*y;

    SchnorrProof proof;

    Schnorr schnorr(G);
    schnorr.prove(y, Y, proof);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof;

    SchnorrProof deserialized;
    serialized >> deserialized;

    BOOST_CHECK(proof.c == deserialized.c);
    BOOST_CHECK(proof.t == deserialized.t);
}

BOOST_AUTO_TEST_CASE(completeness)
{
    GroupElement G;
    G.randomize();

    Scalar y;
    y.randomize();
    GroupElement Y = G*y;

    SchnorrProof proof;

    Schnorr schnorr(G);
    schnorr.prove(y, Y, proof);

    BOOST_CHECK(schnorr.verify(Y, proof));
}

BOOST_AUTO_TEST_CASE(bad_proofs)
{
    GroupElement G;
    G.randomize();

    Scalar y;
    y.randomize();
    GroupElement Y = G*y;

    SchnorrProof proof;

    Schnorr schnorr(G);
    schnorr.prove(y, Y, proof);

    // Bad Y
    GroupElement evil_Y;
    evil_Y.randomize();
    BOOST_CHECK(!(schnorr.verify(evil_Y, proof)));

    // Bad c
    SchnorrProof evil_proof = proof;
    evil_proof.c.randomize();
    BOOST_CHECK(!(schnorr.verify(Y, evil_proof)));

    // Bad t
    evil_proof = proof;
    evil_proof.t.randomize();
    BOOST_CHECK(!(schnorr.verify(Y, evil_proof)));
}

BOOST_AUTO_TEST_SUITE_END()

}
