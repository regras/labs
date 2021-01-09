#include "abs.h"
#include "math/matrix.h"
#include "signature/gpv.h"
#include "signaturecontext.h"
#include "utils/inttypes.h"
#include "utils/memory.h"
#include <stdint.h>
#include <iostream>
#include <memory>
#include <ostream>
#include <ratio>
#include <string>
#include <vector>

using namespace lbcrypto;

///////////////////////////////////////////////////////////////////////////////
//                              Helper functions                             //
///////////////////////////////////////////////////////////////////////////////

// Public Syndrome matrix generator from a given set of attributes
void attributeHashGenerator(vector<string> attributes, shared_ptr<GPVSignatureParameters<Poly>> m_params, Matrix<Poly> *attributesSyndrome) {
    EncodingParams ep(std::make_shared<EncodingParamsImpl>(PlaintextModulus(512)));
    vector<int64_t> digest;
    Poly u;

    for (auto i = attributes.begin(); i != attributes.end(); ++i) {
        for (int j = 0; j < 32; j++) {
            string auxAttr = std::to_string(j) + *i;

            lbcrypto::HashUtil::Hash(auxAttr, lbcrypto::SHA_256, digest);
            lbcrypto::Plaintext hashedText(std::make_shared<lbcrypto::CoefPackedEncoding>(
                                               m_params->GetILParams(), ep, digest));

            // erase the digest value before the next use
            digest.clear();

            hashedText->Encode();
            u = hashedText->GetElement<Poly>();
            u.SwitchFormat();

            // Sums the current attributes with the next one
            (*attributesSyndrome)(0, j) = (*attributesSyndrome)(0, j) + u;
        }
    }

    return;
}

// Public 32 bit digest
uint32_t compactDigest(shared_ptr<GPVSignatureParameters<Poly>> m_params, string message) {
    EncodingParams ep(std::make_shared<EncodingParamsImpl>(PlaintextModulus(512)));
    vector<int64_t> digest;
    uint32_t h = 0;

    lbcrypto::HashUtil::Hash(message, lbcrypto::SHA_256, digest);
    lbcrypto::Plaintext hashedText(std::make_shared<lbcrypto::CoefPackedEncoding>(
                                       m_params->GetILParams(), ep, digest));

    h += ((uint32_t)(digest[0] & 0xFF)) << 24;
    h += ((uint32_t)(digest[1] & 0xFF)) << 16;
    h += ((uint32_t)(digest[2] & 0xFF)) << 8;
    h += ((uint32_t)(digest[3] & 0xFF));
    return h;
}

///////////////////////////////////////////////////////////////////////////////
//                           ABS protocol functions                          //
///////////////////////////////////////////////////////////////////////////////

// Setups the Attribute Authority keys and public parameters
// Dummy for now (using the GPV normal keygen)
void setup() {}

// Extracts an user key using a set of attributes and AA keys
vector<shared_ptr<Matrix<Poly>>> extract(shared_ptr<GPVSignatureParameters<Poly>> m_params,
                                         const lbcrypto::GPVSignKey<Poly> &signKey,
                                         const lbcrypto::GPVVerificationKey<Poly> &verificationKey,
                                         vector<string> attributes) {

    // Getting parameters for calculations
    size_t n = m_params->GetILParams()->GetRingDimension();
    size_t k = m_params->GetK();
    size_t base = m_params->GetBase();

    shared_ptr<typename Poly::Params> params = m_params->GetILParams();
    auto zero_alloc = Poly::Allocator(params, EVALUATION);

    // Generate the syndrome matrix from a set of attributes
    Matrix<Poly> syndromeMatrix(zero_alloc, 1, 32);
    attributeHashGenerator(attributes, m_params, &syndromeMatrix);

    // Getting the trapdoor, its public matrix, perturbation matrix and gaussian
    // generator to use in sampling
    const Matrix<Poly> &A = verificationKey.GetVerificationKey();
    const RLWETrapdoorPair<Poly> &T = signKey.GetSignKey();
    typename Poly::DggType &dgg = m_params->GetDiscreteGaussianGenerator();

    typename Poly::DggType &dggLargeSigma = m_params->GetDiscreteGaussianGeneratorLargeSigma();

    // Set of solutions to the SIS problem will be the users attributes key
    vector<shared_ptr<Matrix<Poly>>> attributesKey;

    // Sample a preimage for each syndrome
    for (int i = 0; i < static_cast<int>(syndromeMatrix.GetCols()); i++) {
        auto u = syndromeMatrix(0, i);
        Matrix<Poly> zHat = RLWETrapdoorUtility<Poly>::GaussSamp(
            n, k, A, T, u, dgg, dggLargeSigma, base);
        attributesKey.push_back(std::make_shared<Matrix<Poly>>(zHat));
    }

    return attributesKey;
}

// Signs a message using an attribute based key
signatureABS sign(shared_ptr<GPVSignatureParameters<Poly>> m_params,
                  vector<shared_ptr<Matrix<Poly>>> attributesKey,
                  const lbcrypto::GPVVerificationKey<Poly> &verificationKey,
                  string message,
                  vector<string> attributeList){

    // Get parameters from keys
    shared_ptr<typename Poly::Params> params = m_params->GetILParams();
    auto stddev = m_params->GetDiscreteGaussianGenerator().GetStd();
    auto zero_alloc = Poly::Allocator(params, EVALUATION);
    auto gaussian_alloc = Poly::MakeDiscreteGaussianCoefficientAllocator(
        params, COEFFICIENT, stddev);

    const Matrix<Poly> &A = verificationKey.GetVerificationKey();

    // Sample a discrete gaussian y vector
    Matrix<Poly> y(zero_alloc, A.GetCols(), A.GetRows(), gaussian_alloc);
    y.SwitchFormat();

    // This will be our secret that will grant the integrity to the signature
    Poly secret = (A * y)(0, 0);

    // The secret will be concatenated with the message and everything will be
    // hashed to a 32 bit tag, represented by a 32 unsigned integer
    string secretWithMessage;

    for (usint i = 0; i < secret.GetLength(); i++) {
        secretWithMessage.append(secret[i].ToString());
    }
    secretWithMessage.append(message);

    // Message tag generation
    uint32_t h = compactDigest(m_params, secretWithMessage);

    // The signature will be a superposition of the SIS solutions (secret
    // attributes keys) summed with the secret gaussian vector y
    Matrix<Poly> sig = y;

    for (int i = 0; i < 32; i++) {
        if ((h >> (31 - i)) & 0x1) {
            sig += *attributesKey[i];
        }
    }

    // The full signature with the parameters consists of:
    // - the attribute list for which this signature is valid
    // - the message tag
    // - the signature lattice point
    signatureABS *signature = new signatureABS(attributeList, h, sig);

    return *signature;
}

// Verifies if the signature is valid for the message and the given attributes
bool verify(shared_ptr<GPVSignatureParameters<Poly>> m_params,
            const lbcrypto::GPVVerificationKey<Poly> &verificationKey,
            string message,
            signatureABS signature){

    // Get common lattice parameters
    shared_ptr<Poly::Params> params = m_params->GetILParams();
    auto zero_alloc = Poly::Allocator(params, EVALUATION);

    // Get the parameters from the signature
    vector<string> attributeList = signature.getAttributeList();
    Matrix<Poly> z = signature.getSignature();
    uint32_t h = signature.getSignatureHash();

    const Matrix<Poly> &A = verificationKey.GetVerificationKey();

    // First part of the signature verification
    Poly sigAux = (A * z)(0, 0);

    // Generate the public matrix for the signature attributes
    Matrix<Poly> syndromeMatrix(zero_alloc, 1, 32);
    attributeHashGenerator(attributeList, m_params, &syndromeMatrix);

    // Second part of the signature verification
    Poly sigAux2(params, EVALUATION, true);

    for (int i = 0; i < 32; i++) {
        if ((h >> (31 - i)) & 0x1) {
            sigAux2 += syndromeMatrix(0, i);
        }
    }

    // Final signature verification computation
    Poly sigHat = sigAux - sigAux2;

    // Serialization of the array to generate the hash tag
    string sigHatString;
    for (uint i = 0; i < sigHat.GetLength(); i++) {
        sigHatString.append(sigHat[i].ToString());
    }
    sigHatString.append(message);

    uint32_t hHat = compactDigest(m_params, sigHatString);

    return h == hHat;
}
