// Copyright Copyright 2024, Horizen Labs, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! Introduce [`Translate`] trait to convert between different versions of the RISC0 library.

use risc0_zkp_v1::verify::VerificationError;

pub trait Translate<T> {
    fn translate(self) -> T;
}

impl Translate<risc0_zkp_v1::core::digest::Digest> for risc0_zkp_v2::core::digest::Digest {
    fn translate(self) -> risc0_zkp_v1::core::digest::Digest {
        self.as_words().try_into().unwrap()
    }
}

impl Translate<risc0_zkp_v2::core::digest::Digest> for risc0_zkp_v1::core::digest::Digest {
    fn translate(self) -> risc0_zkp_v2::core::digest::Digest {
        self.as_words().try_into().unwrap()
    }
}

impl Translate<risc0_zkp_v1::core::digest::Digest> for risc0_zkp_v3::core::digest::Digest {
    fn translate(self) -> risc0_zkp_v1::core::digest::Digest {
        self.as_words().try_into().unwrap()
    }
}

impl Translate<risc0_zkp_v3::core::digest::Digest> for risc0_zkp_v1::core::digest::Digest {
    fn translate(self) -> risc0_zkp_v3::core::digest::Digest {
        self.as_words().try_into().unwrap()
    }
}

impl Translate<risc0_zkp_v2::adapter::ProtocolInfo> for risc0_zkp_v1::adapter::ProtocolInfo {
    fn translate(self) -> risc0_zkp_v2::adapter::ProtocolInfo {
        risc0_zkp_v2::adapter::ProtocolInfo(self.0)
    }
}

impl Translate<risc0_zkp_v1::adapter::ProtocolInfo> for risc0_zkp_v2::adapter::ProtocolInfo {
    fn translate(self) -> risc0_zkp_v1::adapter::ProtocolInfo {
        risc0_zkp_v1::adapter::ProtocolInfo(self.0)
    }
}

impl Translate<risc0_zkp_v3::adapter::ProtocolInfo> for risc0_zkp_v1::adapter::ProtocolInfo {
    fn translate(self) -> risc0_zkp_v3::adapter::ProtocolInfo {
        risc0_zkp_v3::adapter::ProtocolInfo(self.0)
    }
}

impl Translate<risc0_zkp_v1::adapter::ProtocolInfo> for risc0_zkp_v3::adapter::ProtocolInfo {
    fn translate(self) -> risc0_zkp_v1::adapter::ProtocolInfo {
        risc0_zkp_v1::adapter::ProtocolInfo(self.0)
    }
}

impl Translate<VerificationError> for risc0_zkp_v2::verify::VerificationError {
    fn translate(self) -> VerificationError {
        use risc0_zkp_v2::verify::VerificationError as VerificationErrorV2;
        match self {
            VerificationErrorV2::ReceiptFormatError => VerificationError::ReceiptFormatError,
            VerificationErrorV2::ControlVerificationError { control_id } => {
                VerificationError::ControlVerificationError {
                    control_id: control_id.translate(),
                }
            }
            VerificationErrorV2::ImageVerificationError => {
                VerificationError::ImageVerificationError
            }
            VerificationErrorV2::MerkleQueryOutOfRange { idx, rows } => {
                VerificationError::MerkleQueryOutOfRange { idx, rows }
            }
            VerificationErrorV2::InvalidProof => VerificationError::InvalidProof,
            VerificationErrorV2::JournalDigestMismatch => VerificationError::JournalDigestMismatch,
            VerificationErrorV2::ClaimDigestMismatch { expected, received } => {
                VerificationError::ClaimDigestMismatch {
                    expected: expected.translate(),
                    received: received.translate(),
                }
            }
            VerificationErrorV2::UnexpectedExitCode => VerificationError::UnexpectedExitCode,
            VerificationErrorV2::InvalidHashSuite => VerificationError::InvalidHashSuite,
            VerificationErrorV2::VerifierParametersMissing => {
                VerificationError::VerifierParametersMissing
            }
            VerificationErrorV2::VerifierParametersMismatch { expected, received } => {
                VerificationError::VerifierParametersMismatch {
                    expected: expected.translate(),
                    received: received.translate(),
                }
            }
            VerificationErrorV2::ProofSystemInfoMismatch { expected, received } => {
                VerificationError::ProofSystemInfoMismatch {
                    expected: expected.translate(),
                    received: received.translate(),
                }
            }
            VerificationErrorV2::CircuitInfoMismatch { expected, received } => {
                VerificationError::CircuitInfoMismatch {
                    expected: expected.translate(),
                    received: received.translate(),
                }
            }
            VerificationErrorV2::UnresolvedAssumption { digest } => {
                VerificationError::UnresolvedAssumption {
                    digest: digest.translate(),
                }
            }
            _ => unreachable!("unknown VerificationError variant: {:?}", self),
        }
    }
}

impl Translate<VerificationError> for risc0_zkp_v3::verify::VerificationError {
    fn translate(self) -> VerificationError {
        use risc0_zkp_v3::verify::VerificationError as VerificationErrorV3;
        match self {
            VerificationErrorV3::ReceiptFormatError => VerificationError::ReceiptFormatError,
            VerificationErrorV3::ControlVerificationError { control_id } => {
                VerificationError::ControlVerificationError {
                    control_id: control_id.translate(),
                }
            }
            VerificationErrorV3::ImageVerificationError => {
                VerificationError::ImageVerificationError
            }
            VerificationErrorV3::MerkleQueryOutOfRange { idx, rows } => {
                VerificationError::MerkleQueryOutOfRange { idx, rows }
            }
            VerificationErrorV3::InvalidProof => VerificationError::InvalidProof,
            VerificationErrorV3::JournalDigestMismatch => VerificationError::JournalDigestMismatch,
            VerificationErrorV3::ClaimDigestMismatch { expected, received } => {
                VerificationError::ClaimDigestMismatch {
                    expected: expected.translate(),
                    received: received.translate(),
                }
            }
            VerificationErrorV3::UnexpectedExitCode => VerificationError::UnexpectedExitCode,
            VerificationErrorV3::InvalidHashSuite => VerificationError::InvalidHashSuite,
            VerificationErrorV3::VerifierParametersMissing => {
                VerificationError::VerifierParametersMissing
            }
            VerificationErrorV3::VerifierParametersMismatch { expected, received } => {
                VerificationError::VerifierParametersMismatch {
                    expected: expected.translate(),
                    received: received.translate(),
                }
            }
            VerificationErrorV3::ProofSystemInfoMismatch { expected, received } => {
                VerificationError::ProofSystemInfoMismatch {
                    expected: expected.translate(),
                    received: received.translate(),
                }
            }
            VerificationErrorV3::CircuitInfoMismatch { expected, received } => {
                VerificationError::CircuitInfoMismatch {
                    expected: expected.translate(),
                    received: received.translate(),
                }
            }
            VerificationErrorV3::UnresolvedAssumption { digest } => {
                VerificationError::UnresolvedAssumption {
                    digest: digest.translate(),
                }
            }
            _ => unreachable!("unknown VerificationError variant: {:?}", self),
        }
    }
}
