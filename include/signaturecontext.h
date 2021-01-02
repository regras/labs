// @file signaturecontext.h - Header file for SignatureContext class, which is
// used for digital signature schemes
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef SIGNATURE_SIGNATURECONTEXT_H
#define SIGNATURE_SIGNATURECONTEXT_H

#include <memory>

#include "gpv.h"
#include "abs.h"

namespace lbcrypto {
/**
 *@brief Context class for signature schemes, including GPV
 *@tparam Element ring element
 */
  template <class Element>
  class SignatureContext {
    public:
      /*
       *@brief Default constructor
       */
      SignatureContext() {}
      /**
       *@brief Method for setting up a GPV context with specific parameters
       *@param ringsize Desired ringsize
       *@param bitwidth Desired modulus bitwidth
       *@param base Base of the gadget matrix
       */
      void GenerateGPVContext(usint ringsize, usint bitwidth, usint base);
      /**
       *@brief Method for setting up a GPV context with desired ring size only
       *@param ringsize Desired ring size
       */
      void GenerateGPVContext(usint ringsize);
      /**
       *@brief Method for key generation
       *@param sk Signing key for sign operation - Output
       *@param vk Verification key for verify operation - Output
       */
      void KeyGen(LPSignKey<Element>* sk, LPVerificationKey<Element>* vk);
      /**
       *@brief Method for offline phase of signing a given plaintext
       *@param pt Plaintext to be signed
       *@param sk Sign key
       *@param pv Perturbation vector sampled - Output
       */
      void SignOfflinePhase(const LPSignKey<Element>& signKey,
                            PerturbationVector<Element>& pv);
      /**
       *@brief Method for online phase of signing a given plaintext
       *@param pt Plaintext to be signed
       *@param sk Sign key
       *@param vk Verification key
       *@param pv Perturbation vector sampled in the offline phase of signing
       *operation
       *@param sign Signature corresponding to the plaintext - Output
       */
      void SignOnlinePhase(const LPSignPlaintext<Element>& pt,
                           const LPSignKey<Element>& sk,
                           const LPVerificationKey<Element>& vk,
                           const PerturbationVector<Element> pv,
                           LPSignature<Element>* signatureText);
      /**
       *@brief Method for key generation
       *@param sk Signing key for sign operation - Output
       *@param vk Verification key for verify operation - Output
       */
      void Setup(LPSignKey<Element>* sk, LPVerificationKey<Element>* vk);

      vector<shared_ptr<Matrix<Poly>>> Extract(const LPSignKey<Element>& sk,
                                               const LPVerificationKey<Element>& vk,
                                               vector<string> attributes);
      signatureABS Sign(const LPVerificationKey<Element>& vk,
                                       vector<shared_ptr<Matrix<Poly>>> attributesKey,
                                       vector<string> attributeList,
                                       string message);
      bool Verify(const LPVerificationKey<Element>& vk,
                  signatureABS signature,
                  string message);

    private:
      // The signature scheme used
      shared_ptr<LPSignatureScheme<Element>> m_scheme;
      // Parameters related to the scheme
      shared_ptr<LPSignatureParameters<Element>> m_params;
  };

}  // namespace lbcrypto

#endif
