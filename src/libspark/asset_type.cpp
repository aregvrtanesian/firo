#include "asset_type.h"

namespace spark {

AssetType::AssetType(const GroupElement& F_, const GroupElement& G_, const GroupElement& H_):
    F(F_), G(G_), H(H_) {
}

Scalar AssetType::challenge(const std::vector<GroupElement>& C, const GroupElement& A, const GroupElement& B) {
    Transcript transcript(LABEL_TRANSCRIPT_ASSET_TYPE_PROOF);
    transcript.add("F", F);
    transcript.add("G", G);
    transcript.add("H", H);
    transcript.add("C", C);
    transcript.add("A", A);
    transcript.add("B", B);

    return transcript.challenge("c");
}

void AssetType::prove(const Scalar& x, const std::vector<Scalar>& y, const std::vector<Scalar>& z, const std::vector<GroupElement>& C, AssetTypeProof& proof) {
    // Check statement validity
    std::size_t n = y.size();
    if (!(z.size() == n && C.size() == n)) {
        throw std::invalid_argument("Bad asset type statement!");
    }
    for (std::size_t i = 0; i < n; i++) {
        if (!(F*x + G*y[i] + H*z[i] == C[i])) {
            throw std::invalid_argument("Bad asset type statement!");
        }
    }

    Scalar rx, ry, rz, sy, sz;
    rx.randomize();
    ry.randomize();
    rz.randomize();
    sy.randomize();
    sz.randomize();

    proof.A = F*rx + G*ry + H*rz;
    proof.B = G*sy + H*sz;

    Scalar c = challenge(C, proof.A, proof.B);

    proof.tx = rx + c*x;
    proof.ty = ry + c*y[0];
    proof.tz = rz + c*z[0];

    proof.uy = sy;
    proof.uz = sz;
    Scalar c_power(c);
    for (std::size_t i = 1; i < n; i++) {
        proof.uy += c_power*(y[i] - y[0]);
        proof.uz += c_power*(z[i] - z[0]);
        c_power *= c;
    }
}

bool AssetType::verify(const std::vector<GroupElement>& C, AssetTypeProof& proof) {
    std::size_t n = C.size();

    Scalar c = challenge(C, proof.A, proof.B);
    std::vector<Scalar> c_powers;
    c_powers.emplace_back(c);
    for (std::size_t i = 1; i < n-1; i++) {
        c_powers.emplace_back(c_powers[i-1]*c);
    }

    // Weight the verification equations
    Scalar w;
    while (w.isZero()) {
        w.randomize();
    }

    std::vector<Scalar> scalars;
    std::vector<GroupElement> points;
    scalars.reserve(5 + n);
    points.reserve(5 + n);

    // F
    scalars.emplace_back(proof.tx);
    points.emplace_back(F);

    // G
    scalars.emplace_back(proof.ty - w*proof.uy);
    points.emplace_back(G);

    // H
    scalars.emplace_back(proof.tz - w*proof.uz);
    points.emplace_back(H);

    // A
    scalars.emplace_back(Scalar((uint64_t) 1).negate());
    points.emplace_back(proof.A);

    // B
    scalars.emplace_back(w);
    points.emplace_back(proof.B);

    // C[0]
    Scalar C0_scalar;
    for (std::size_t i = 1; i < n; i++) {
        C0_scalar += c_powers[i-1];
    }
    C0_scalar *= w;
    C0_scalar += c_powers[0];
    C0_scalar = C0_scalar.negate();
    scalars.emplace_back(C0_scalar);
    points.emplace_back(C[0]);

    // {C}
    for (std::size_t i = 1; i < n; i++) {
        scalars.emplace_back(w*c_powers[i-1]);
        points.emplace_back(C[i]);
    }

    secp_primitives::MultiExponent multiexp(points, scalars);
    return multiexp.get_multiple().isInfinity();
}

}
