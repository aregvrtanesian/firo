#include "schnorr.h"

namespace spark {

Schnorr::Schnorr(const std::vector<GroupElement>& G_):
    G(G_) {
}

Scalar Schnorr::challenge(
        const GroupElement& Y,
        const GroupElement& A) {
    Transcript transcript(LABEL_TRANSCRIPT_SCHNORR_PROOF);
    transcript.add("G", G);
    transcript.add("Y", Y);
    transcript.add("A", A);

    return transcript.challenge("c");
}

void Schnorr::prove(const std::vector<Scalar>& y, const GroupElement& Y, SchnorrProof& proof) {
    // Check statement validity
    GroupElement temp;
    std::size_t n = G.size();
    if (y.size() != n) {
        throw std::invalid_argument("Bad Schnorr vector size!");
    }
    for (std::size_t i = 0; i < n; i++) {
        temp += G[i]*y[i];
    }
    if (!(temp == Y)) {
        throw std::invalid_argument("Bad Schnorr statement!");
    }

    std::vector<Scalar> r;
    r.resize(n);
    proof.A = GroupElement();
    for (std::size_t i = 0; i < n; i++) {
        r[i].randomize();
        proof.A += G[i]*r[i];
    }

    Scalar c = challenge(Y, proof.A);

    proof.t.resize(n);
    for (std::size_t i = 0; i < n; i++) {
        proof.t[i] = r[i] + c*y[i];
    }
}

bool Schnorr::verify(const GroupElement& Y, SchnorrProof& proof) {
    // Check proof semantics
    std::size_t n = G.size();
    if (proof.t.size() != n) {
        return false;
    }

    Scalar c = challenge(Y, proof.A);

    std::vector<Scalar> scalars;
    std::vector<GroupElement> points;
    scalars.reserve(n + 2);
    points.reserve(n + 2);

    for (std::size_t i = 0; i < n; i++) {
        scalars.emplace_back(proof.t[i]);
        points.emplace_back(G[i]);
    }
    scalars.emplace_back(Scalar(uint64_t(1)).negate());
    points.emplace_back(proof.A);
    scalars.emplace_back(c.negate());
    points.emplace_back(Y);

    secp_primitives::MultiExponent multiexp(points, scalars);
    return multiexp.get_multiple().isInfinity();
}

}
