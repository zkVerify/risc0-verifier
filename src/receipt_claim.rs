// Copyright Copyright 2024, Horizen Labs, Inc.
// Copyright Copyright 2024 RISC Zero, Inc.
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

//! [ReceiptClaim] and associated types and functions.
//!
//! A [ReceiptClaim] struct contains the public claims (i.e. public outputs) of a zkVM guest
//! execution, such as the journal committed to by the guest. It also includes important
//! information such as the exit code and the starting and ending system state (i.e. the state of
//! memory).
extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};
use anyhow::{anyhow, ensure};
use core::{fmt, ops::Deref};

// use anyhow::{anyhow, ensure};
use risc0_binfmt::{
    read_sha_halfs, tagged_list, tagged_list_cons, tagged_struct, write_sha_halfs,
    DecodeError as SysDecodeError, Digestible, ExitCode, InvalidExitCodeError, SystemState,
};
use risc0_zkp::core::{
    digest::Digest,
    hash::{sha, sha::Sha256},
};
use serde::{Deserialize, Serialize};

// TODO(victor): Add functions to handle the `ReceiptClaim` transformations conducted as part of
// join, resolve, and eventually resume calls. This will allow these to be used for recursion, as
// well as dev mode recursion, and composite receipts.

/// Public claims about a zkVM guest execution, such as the journal committed to by the guest.
///
/// Also includes important information such as the exit code and the starting and ending system
/// state (i.e. the state of memory). [ReceiptClaim] is a "Merkle-ized struct" supporting
/// partial openings of the underlying fields from a hash commitment to the full structure. Also
/// see [MaybePruned].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ReceiptClaim {
    /// The [SystemState] just before execution has begun.
    pub pre: MaybePruned<SystemState>,

    /// The [SystemState] just after execution has completed.
    pub post: MaybePruned<SystemState>,

    /// The exit code for the execution.
    pub exit_code: ExitCode,

    /// Input to the guest.
    pub input: MaybePruned<Option<Input>>,

    /// [Output] of the guest, including the journal and assumptions set during execution.
    pub output: MaybePruned<Option<Output>>,
}

impl ReceiptClaim {
    /// Construct a [ReceiptClaim] representing a zkVM execution that eneded normally (i.e.
    /// Halted(0)) with the given image ID and journal.
    pub fn ok(
        image_id: impl Into<Digest>,
        journal: impl Into<MaybePruned<Vec<u8>>>,
    ) -> ReceiptClaim {
        Self {
            pre: MaybePruned::Pruned(image_id.into()),
            post: MaybePruned::Value(SystemState {
                pc: 0,
                merkle_root: Digest::ZERO,
            }),
            exit_code: ExitCode::Halted(0),
            input: None.into(),
            output: Some(Output {
                journal: journal.into(),
                assumptions: MaybePruned::Pruned(Digest::ZERO),
            })
            .into(),
        }
    }

    /// Construct a [ReceiptClaim] representing a zkVM execution that eneded in a normal paused
    /// state (i.e. Paused(0)) with the given image ID and journal.
    pub fn paused(
        image_id: impl Into<Digest>,
        journal: impl Into<MaybePruned<Vec<u8>>>,
    ) -> ReceiptClaim {
        Self {
            pre: MaybePruned::Pruned(image_id.into()),
            post: MaybePruned::Value(SystemState {
                pc: 0,
                merkle_root: Digest::ZERO,
            }),
            exit_code: ExitCode::Paused(0),
            input: None.into(),
            output: Some(Output {
                journal: journal.into(),
                assumptions: MaybePruned::Pruned(Digest::ZERO),
            })
            .into(),
        }
    }

    /// Decode a [ReceiptClaim] from a list of [u32]'s
    pub fn decode(flat: &mut VecDeque<u32>) -> Result<Self, DecodeError> {
        let input = read_sha_halfs(flat)?;
        let pre = SystemState::decode(flat)?;
        let post = SystemState::decode(flat)?;
        let sys_exit = flat.pop_front().ok_or(SysDecodeError::EndOfStream)?;
        let user_exit = flat.pop_front().ok_or(SysDecodeError::EndOfStream)?;
        let exit_code = ExitCode::from_pair(sys_exit, user_exit)?;
        let output = read_sha_halfs(flat)?;

        Ok(Self {
            input: MaybePruned::Pruned(input),
            pre: pre.into(),
            post: post.into(),
            exit_code,
            output: MaybePruned::Pruned(output),
        })
    }

    /// Encode a [ReceiptClaim] to a list of [u32]'s
    pub fn encode(&self, flat: &mut Vec<u32>) -> Result<(), PrunedValueError> {
        write_sha_halfs(flat, &self.input.digest::<sha::Impl>());
        self.pre.as_value()?.encode(flat);
        self.post.as_value()?.encode(flat);
        let (sys_exit, user_exit) = self.exit_code.into_pair();
        flat.push(sys_exit);
        flat.push(user_exit);
        write_sha_halfs(flat, &self.output.digest::<sha::Impl>());
        Ok(())
    }
}

impl Digestible for ReceiptClaim {
    /// Hash the [ReceiptClaim] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        let (sys_exit, user_exit) = self.exit_code.into_pair();
        tagged_struct::<S>(
            "risc0.ReceiptClaim",
            &[
                self.input.digest::<S>(),
                self.pre.digest::<S>(),
                self.post.digest::<S>(),
                self.output.digest::<S>(),
            ],
            &[sys_exit, user_exit],
        )
    }
}

/// Error returned when decoding [ReceiptClaim] fails.
#[derive(Debug, Copy, Clone)]
pub enum DecodeError {
    /// Decoding failure due to an invalid exit code.
    InvalidExitCode(InvalidExitCodeError),
    /// Decoding failure due to an inner decoding failure.
    Decode(SysDecodeError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidExitCode(e) => write!(f, "failed to decode receipt claim: {e}"),
            Self::Decode(e) => write!(f, "failed to decode receipt claim: {e}"),
        }
    }
}

impl From<SysDecodeError> for DecodeError {
    fn from(e: SysDecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<InvalidExitCodeError> for DecodeError {
    fn from(e: InvalidExitCodeError) -> Self {
        Self::InvalidExitCode(e)
    }
}

/// A type representing an unknown claim type.
///
/// A receipt (e.g. [SuccinctReceipt][crate::SuccinctReceipt]) may have an unknown claim type when
/// only the digest of the claim is needed, and the full claim value is cannot be determined by the
/// compiler. This allows for a collection of receipts to be created even when the underlying
/// claims are of heterogeneous types (e.g. Vec<SuccinctReceipt<Unknown>>).
///
/// Note that this in an uninhabited type, simmilar to the [never type].
///
/// [never type]: https://doc.rust-lang.org/std/primitive.never.html
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Unknown {}

impl Digestible for Unknown {
    fn digest<S: Sha256>(&self) -> Digest {
        match *self { /* unreachable  */ }
    }
}

/// Input field in the [ReceiptClaim], committing to a public value accessible to the guest.
///
/// NOTE: This type is currently uninhabited (i.e. it cannot be constructed), and only its digest
/// is accessible. It may become inhabited in a future release.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Input {
    // Private field to ensure this type cannot be constructed.
    // By making this type uninhabited, it can be populated later without breaking backwards
    // compatibility.
    pub(crate) x: Unknown,
}

impl Digestible for Input {
    /// Hash the [Input] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        match self.x { /* unreachable  */ }
    }
}

/// Output field in the [ReceiptClaim], committing to a claimed journal and assumptions list.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Output {
    /// The journal committed to by the guest execution.
    pub journal: MaybePruned<Vec<u8>>,

    /// An ordered list of [ReceiptClaim] digests corresponding to the
    /// calls to `env::verify` and `env::verify_integrity`.
    ///
    /// Verifying the integrity of a [crate::Receipt] corresponding to a [ReceiptClaim] with a
    /// non-empty assumptions list does not guarantee unconditionally any of the claims over the
    /// guest execution (i.e. if the assumptions list is non-empty, then the journal digest cannot
    /// be trusted to correspond to a genuine execution). The claims can be checked by additional
    /// verifying a [crate::Receipt] for every digest in the assumptions list.
    pub assumptions: MaybePruned<Assumptions>,
}

impl Digestible for Output {
    /// Hash the [Output] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>(
            "risc0.Output",
            &[self.journal.digest::<S>(), self.assumptions.digest::<S>()],
            &[],
        )
    }
}

/// An [assumption] made in the course of proving program execution.
///
/// Assumptions are generated when the guest makes a recursive verification call. Each assumption
/// commits the statement, such that only a receipt proving that statement can be used to resolve
/// and remove the assumption.
///
/// [assumption]: https://dev.risczero.com/terminology#assumption
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Assumption {
    /// Commitment to the assumption claim. It may be the digest of a [ReceiptClaim], or it could
    /// be the digest of the claim for a different circuit such as an accelerator.
    pub claim: Digest,

    /// Commitment to the set of [recursion programs] that can be used to resolve this assumption.
    ///
    /// Binding the set of recursion programs also binds the circuits, and creates an assumption
    /// resolved by independent set of circuits (e.g. keccak or Groth16 verify). Proofs of these
    /// external claims are verified by a "lift" program implemented for the recursion VM which
    /// brings the claim into the recursion system. This lift program is committed to in the
    /// control root.
    ///
    /// A special value of all zeroes indicates "self-composition", where the control root used to
    /// verify this claim is also used to verify the assumption.
    ///
    /// [recursion programs]: https://dev.risczero.com/terminology#recursion-program
    pub control_root: Digest,
}

impl Digestible for Assumption {
    /// Hash the [Assumption] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_struct::<S>("risc0.Assumption", &[self.claim, self.control_root], &[])
    }
}

/// A list of assumptions, each a [Digest] or populated value of an [Assumption].
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Assumptions(pub Vec<MaybePruned<Assumption>>);

impl Assumptions {
    /// Add an assumption to the head of the assumptions list.
    pub fn add(&mut self, assumption: MaybePruned<Assumption>) {
        self.0.insert(0, assumption);
    }

    /// Mark an assumption as resolved and remove it from the list.
    ///
    /// Assumptions can only be removed from the head of the list.
    pub fn resolve(&mut self, resolved: &Digest) -> anyhow::Result<()> {
        let head = self
            .0
            .first()
            .ok_or_else(|| anyhow!("cannot resolve assumption from empty list"))?;

        ensure!(
            &head.digest::<sha::Impl>() == resolved,
            "resolved assumption is not equal to the head of the list: {} != {}",
            resolved,
            head.digest::<sha::Impl>()
        );

        // Drop the head of the assumptions list.
        self.0 = self.0.split_off(1);
        Ok(())
    }
}

impl Deref for Assumptions {
    type Target = [MaybePruned<Assumption>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Digestible for Assumptions {
    /// Hash the [Assumptions] to get a digest of the struct.
    fn digest<S: Sha256>(&self) -> Digest {
        tagged_list::<S>(
            "risc0.Assumptions",
            &self.0.iter().map(|a| a.digest::<S>()).collect::<Vec<_>>(),
        )
    }
}

impl MaybePruned<Assumptions> {
    /// Check if the (possibly pruned) assumptions list is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            MaybePruned::Value(list) => list.is_empty(),
            MaybePruned::Pruned(digest) => digest == &Digest::ZERO,
        }
    }

    /// Add an assumption to the head of the assumptions list.
    ///
    /// If this value is pruned, then the result will also be a pruned value.
    pub fn add(&mut self, assumption: MaybePruned<Assumption>) {
        match self {
            MaybePruned::Value(list) => list.add(assumption),
            MaybePruned::Pruned(list_digest) => {
                *list_digest = tagged_list_cons::<sha::Impl>(
                    "risc0.Assumptions",
                    &assumption.digest::<sha::Impl>(),
                    &*list_digest,
                );
            }
        }
    }

    /// Mark an assumption as resolved and remove it from the list.
    ///
    /// Assumptions can only be removed from the head of the list. If this value
    /// is pruned, then the result will also be a pruned value. The `tail`
    /// parameter should be equal to the digest of the list after the
    /// resolved assumption is removed.
    pub fn resolve(&mut self, resolved: &Digest, tail: &Digest) -> anyhow::Result<()> {
        match self {
            MaybePruned::Value(list) => list.resolve(resolved),
            MaybePruned::Pruned(list_digest) => {
                let reconstructed =
                    tagged_list_cons::<sha::Impl>("risc0.Assumptions", resolved, tail);
                ensure!(
                    &reconstructed == list_digest,
                    "reconstructed list digest does not match; expected {}, reconstructed {}",
                    list_digest,
                    reconstructed
                );

                // Set the pruned digest value to be equal to the rest parameter.
                *list_digest = *tail;
                Ok(())
            }
        }
    }
}

impl From<Vec<MaybePruned<Assumption>>> for Assumptions {
    fn from(value: Vec<MaybePruned<Assumption>>) -> Self {
        Self(value)
    }
}

impl From<Vec<Assumption>> for Assumptions {
    fn from(value: Vec<Assumption>) -> Self {
        Self(value.into_iter().map(Into::into).collect())
    }
}

impl From<Vec<Assumption>> for MaybePruned<Assumptions> {
    fn from(value: Vec<Assumption>) -> Self {
        Self::Value(value.into())
    }
}

/// Either a source value or a hash [Digest] of the source value.
///
/// This type supports creating "Merkle-ized structs". Each field of a Merkle-ized struct can have
/// either the full value, or it can be "pruned" and replaced with a digest committing to that
/// value. One way to think of this is as a special Merkle tree of a predefined shape. Each field
/// is a child node. Any field/node in the tree can be opened by providing the Merkle inclusion
/// proof. When a subtree is pruned, the digest commits to the value of all contained fields.
/// [ReceiptClaim] is the motivating example of this type of Merkle-ized struct.
#[derive(Clone, Deserialize, Serialize)]
pub enum MaybePruned<T>
where
    T: Clone + Serialize,
{
    /// Unpruned value.
    Value(T),

    /// Pruned value, which is a hash [Digest] of the value.
    Pruned(Digest),
}

impl<T> MaybePruned<T>
where
    T: Clone + Serialize,
{
    /// Unwrap the value, or return an error.
    pub fn value(self) -> Result<T, PrunedValueError> {
        match self {
            MaybePruned::Value(value) => Ok(value),
            MaybePruned::Pruned(digest) => Err(PrunedValueError(digest)),
        }
    }

    /// Unwrap the value as a reference, or return an error.
    pub fn as_value(&self) -> Result<&T, PrunedValueError> {
        match self {
            MaybePruned::Value(ref value) => Ok(value),
            MaybePruned::Pruned(ref digest) => Err(PrunedValueError(*digest)),
        }
    }

    /// Unwrap the value as a mutable reference, or return an error.
    pub fn as_value_mut(&mut self) -> Result<&mut T, PrunedValueError> {
        match self {
            MaybePruned::Value(ref mut value) => Ok(value),
            MaybePruned::Pruned(ref digest) => Err(PrunedValueError(*digest)),
        }
    }
}

impl<T> From<T> for MaybePruned<T>
where
    T: Clone + Serialize,
{
    fn from(value: T) -> Self {
        Self::Value(value)
    }
}

impl<T> Digestible for MaybePruned<T>
where
    T: Digestible + Clone + Serialize,
{
    fn digest<S: Sha256>(&self) -> Digest {
        match self {
            MaybePruned::Value(ref val) => val.digest::<S>(),
            MaybePruned::Pruned(digest) => *digest,
        }
    }
}

impl<T> Default for MaybePruned<T>
where
    T: Digestible + Default + Clone + Serialize,
{
    fn default() -> Self {
        MaybePruned::Value(Default::default())
    }
}

impl<T> MaybePruned<Option<T>>
where
    T: Clone + Serialize,
{
    /// Returns true is the value is None, or the value is pruned as the zero
    /// digest.
    pub fn is_none(&self) -> bool {
        match self {
            MaybePruned::Value(Some(_)) => false,
            MaybePruned::Value(None) => true,
            MaybePruned::Pruned(digest) => digest == &Digest::ZERO,
        }
    }

    /// Returns true is the value is Some(_), or the value is pruned as a
    /// non-zero digest.
    pub fn is_some(&self) -> bool {
        !self.is_none()
    }
}

#[cfg(test)]
impl<T> PartialEq for MaybePruned<T>
where
    T: Clone + Serialize + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Value(a), Self::Value(b)) => a == b,
            (Self::Pruned(a), Self::Pruned(b)) => a == b,
            _ => false,
        }
    }
}

impl<T> fmt::Debug for MaybePruned<T>
where
    T: Clone + Serialize + Digestible + fmt::Debug,
{
    /// Format [MaybePruned] values are if they were a struct with value and
    /// digest fields. Digest field is always provided so that divergent
    /// trees of [MaybePruned] values can be compared.
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = fmt.debug_struct("MaybePruned");
        if let MaybePruned::Value(value) = self {
            builder.field("value", value);
        }
        builder
            .field("digest", &self.digest::<sha::Impl>())
            .finish()
    }
}

/// Error returned when the source value was pruned, and is not available.
#[derive(Debug, Clone)]
pub struct PrunedValueError(pub Digest);

impl fmt::Display for PrunedValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "value is pruned: {}", &self.0)
    }
}
