#include "../asset_type.h"
#include "../../streams.h"
#include "../../version.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

BOOST_FIXTURE_TEST_SUITE(spark_asset_type_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(serialization)
{
    GroupElement F, G, H;
    F.randomize();
    G.randomize();
    H.randomize();

    const std::size_t n = 3;

    Scalar x;
    std::vector<Scalar> y, z;
    x.randomize();
    y.resize(n);
    z.resize(n);
    std::vector<GroupElement> C;
    C.resize(n);
    for (std::size_t i = 0; i < n; i++) {
        y[i].randomize();
        z[i].randomize();

        C[i] = F*x + G*y[i] + H*z[i];
    }

    AssetTypeProof proof;

    AssetType asset(F, G, H);
    asset.prove(x, y, z, C, proof);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof;

    AssetTypeProof deserialized;
    serialized >> deserialized;

    BOOST_CHECK(proof.A == deserialized.A);
    BOOST_CHECK(proof.B == deserialized.B);
    BOOST_CHECK(proof.tx == deserialized.tx);
    BOOST_CHECK(proof.ty == deserialized.ty);
    BOOST_CHECK(proof.tz == deserialized.tz);
    BOOST_CHECK(proof.uy == deserialized.uy);
    BOOST_CHECK(proof.uz == deserialized.uz);
}

BOOST_AUTO_TEST_CASE(completeness)
{
    GroupElement F, G, H;
    F.randomize();
    G.randomize();
    H.randomize();

    const std::size_t n = 3;

    Scalar x;
    std::vector<Scalar> y, z;
    x.randomize();
    y.resize(n);
    z.resize(n);
    std::vector<GroupElement> C;
    C.resize(n);
    for (std::size_t i = 0; i < n; i++) {
        y[i].randomize();
        z[i].randomize();

        C[i] = F*x + G*y[i] + H*z[i];
    }

    AssetTypeProof proof;

    AssetType asset(F, G, H);
    asset.prove(x, y, z, C, proof);

    BOOST_CHECK(asset.verify(C, proof));
}

BOOST_AUTO_TEST_CASE(bad_proofs)
{
    GroupElement F, G, H;
    F.randomize();
    G.randomize();
    H.randomize();

    const std::size_t n = 3;

    Scalar x;
    std::vector<Scalar> y, z;
    x.randomize();
    y.resize(n);
    z.resize(n);
    std::vector<GroupElement> C;
    C.resize(n);
    for (std::size_t i = 0; i < n; i++) {
        y[i].randomize();
        z[i].randomize();

        C[i] = F*x + G*y[i] + H*z[i];
    }

    AssetTypeProof proof;

    AssetType asset(F, G, H);
    asset.prove(x, y, z, C, proof);

    // Bad C
    for (std::size_t i = 0; i < n; i++) {
        std::vector<GroupElement> evil_C(C);
        evil_C[i].randomize();
        BOOST_CHECK(!(asset.verify(evil_C, proof)));
    }

    // Bad A
    AssetTypeProof evil_proof = proof;
    evil_proof.A.randomize();
    BOOST_CHECK(!(asset.verify(C, evil_proof)));

    // Bad B
    evil_proof = proof;
    evil_proof.B.randomize();
    BOOST_CHECK(!(asset.verify(C, evil_proof)));

    // Bad tx
    evil_proof = proof;
    evil_proof.tx.randomize();
    BOOST_CHECK(!(asset.verify(C, evil_proof)));

    // Bad ty
    evil_proof = proof;
    evil_proof.ty.randomize();
    BOOST_CHECK(!(asset.verify(C, evil_proof)));

    // Bad tz
    evil_proof = proof;
    evil_proof.tz.randomize();
    BOOST_CHECK(!(asset.verify(C, evil_proof)));

    // Bad uy
    evil_proof = proof;
    evil_proof.uy.randomize();
    BOOST_CHECK(!(asset.verify(C, evil_proof)));

    // Bad uz
    evil_proof = proof;
    evil_proof.uz.randomize();
    BOOST_CHECK(!(asset.verify(C, evil_proof)));
}

BOOST_AUTO_TEST_SUITE_END()

}
