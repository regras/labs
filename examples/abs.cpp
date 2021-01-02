// @file gpv.cpp - Example for GPV signature scheme
//
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

#include <ostream>
#include "signaturecontext.h"
#include "abs.h"

using namespace lbcrypto;
int main() {

  /////////////////////////////////////////////////////////////////////////////
  //                     Pre-setup GPV lattice parameters                    //
  /////////////////////////////////////////////////////////////////////////////

  std::cout << "This is a demo file of an ABS signature scheme" << std::endl
            << std::endl;
  // We generate a signature context and make it a GPV context with ring size,
  // you can also explicitly define ringsize, modulus bitwidth and base
  SignatureContext<Poly> context;
  usint ringsize = 1024;
  std::cout << "Used ring size for calculations: " << ringsize << std::endl;
  std::cout << "Generating context for GPV (AA) signature" << std::endl << std::endl;
  context.GenerateGPVContext(ringsize);

  /////////////////////////////////////////////////////////////////////////////
  //                    Setuping the AA (normal GPV keygen)                  //
  /////////////////////////////////////////////////////////////////////////////

  // Create our sign and verification keys and generate them
  GPVVerificationKey<Poly> vk;
  GPVSignKey<Poly> sk;
  std::cout << "Generating AA's signing and verification keys" << std::endl;
  context.Setup(&sk, &vk);

  /////////////////////////////////////////////////////////////////////////////
  //                       Extracting the attribute keys                     //
  /////////////////////////////////////////////////////////////////////////////

  std::cout << "Generating users attribute keys" << std::endl;

  // NOTE: In this PoC the attributes are just strings and the signature and
  // verification must be exactly the same ones. In future works, we should use
  // FHE properties of lattices or other ways to generate keys so that it is
  // possible to flexibilize the granularity of the signatures.
  vector<string> attributesUser1;
  vector<string> attributesUser2;

  // Graduate, Professor, E.E.
  attributesUser1.push_back(attributesList[1]);
  attributesUser1.push_back(attributesList[2]);
  attributesUser1.push_back(attributesList[3]);

  // Undergrad, C.S., CP > 80
  attributesUser1.push_back(attributesList[0]);
  attributesUser1.push_back(attributesList[4]);
  attributesUser1.push_back(attributesList[5]);

  vector<shared_ptr<Matrix<Poly>>>user1AttrKey = context.Extract(sk, vk, attributesUser1);
  vector<shared_ptr<Matrix<Poly>>>user2AttrKey = context.Extract(sk, vk, attributesUser2);

  std::cout << std::endl;

  /////////////////////////////////////////////////////////////////////////////
  //                            Signing a message                            //
  /////////////////////////////////////////////////////////////////////////////

  string pt1 = "This is a text";
  string pt2 = "This is also a text";

  // Sign the first plaintext with generated keys
  std::cout << "Signing first plaintext with user 1" << std::endl;
  signatureABS signature1User1 = context.Sign(vk, user1AttrKey, attributesUser1, pt1);

  std::cout << "Signing first plaintext with user 2" << std::endl;
  signatureABS signature1User2 = context.Sign(vk, user2AttrKey, attributesUser2, pt1);

  std::cout << std::endl;

  /////////////////////////////////////////////////////////////////////////////
  //                         Verifying a signature                           //
  /////////////////////////////////////////////////////////////////////////////

  // Try to verify the signature with two different plaintexts
  std::cout << "Trying to verify the signature with different attributes and plaintexts " << std::endl;

  // Verifying signature 1 of user 1, using pt1 and user 1 attributes
  bool result1 = context.Verify(vk, signature1User1, pt1);

  // Verifying signature 1 of user 2, using pt1 and user 2 attributes
  bool result2 = context.Verify(vk, signature1User2, pt1);

  // Trying to verify signature 1 of user 1, using pt2 and user 1 attributes
  bool result3 = context.Verify(vk, signature1User1, pt2);

  // Change the list of attributes for signature 2
  signature1User2.setAttributeList(attributesUser1);
  // Trying to verify signature 1 of user 2, using pt1 and user 1 attributes
  bool result4 = context.Verify(vk, signature1User2, pt1);

  std::cout << "Verif result 1 (signature of pt1, from user 1, with user 1 attributes, on message pt1): " << result1 << std::endl;
  std::cout << "Verif result 2 (signature of pt1, from user 2, with user 2 attributes, on message pt1): " << result2 << std::endl;
  std::cout << "Verif result 3 (signature of pt1, from user 1, with user 1 attributes, on message pt2): " << result3 << std::endl;
  std::cout << "Verif result 4 (signature of pt1, from user 2, with user 1 attributes, on message pt1): " << result4 << std::endl;
  return 0;
}
