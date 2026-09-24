// Copyright (C) 2026 — fuzz harness (fork branch, not upstream Monad code).
//
// Network-reachable RLP decode fuzz target: feeds raw bytes to every public
// RLP decoder entry point (transactions, blocks, receipts, withdrawals,
// access/authorization lists, and the core string/address decoders). Any
// out-of-bounds access, integer overflow, or UB is caught by ASan/UBSan.
//
// This exercises the exact boundary the scope names: "malformed RLP" reaching
// the C++ execution layer.

#include <category/core/byte_string.hpp>
#include <category/execution/ethereum/rlp/decode.hpp>
#include <category/execution/ethereum/core/rlp/transaction_rlp.hpp>
#include <category/execution/ethereum/core/rlp/block_rlp.hpp>
#include <category/execution/ethereum/core/rlp/receipt_rlp.hpp>
#include <category/execution/ethereum/core/rlp/withdrawal_rlp.hpp>
#include <category/execution/ethereum/core/rlp/address_rlp.hpp>
#include <category/execution/ethereum/core/rlp/int_rlp.hpp>
#include <category/execution/ethereum/core/rlp/signature_rlp.hpp>

#include <cstdint>
#include <cstddef>

using namespace monad;
using namespace monad::rlp;

namespace
{
    // Each decoder mutates the view it is given, so every call gets a fresh
    // copy of the raw input.
    template <typename Fn>
    void attempt(Fn fn, byte_string_view const raw)
    {
        byte_string_view v = raw;
        (void)fn(v);
    }
}

extern "C" int
LLVMFuzzerTestOneInput(uint8_t const *const data, size_t const size)
{
    byte_string_view const raw{data, size};

    // Transactions
    attempt(decode_transaction, raw);
    attempt(decode_transaction_legacy, raw);
    attempt(decode_transaction_list, raw);
    attempt(decode_access_list, raw);
    attempt(decode_access_entry, raw);
    attempt(decode_authorization_list, raw);
    attempt(decode_authorization_entry, raw);

    // Blocks
    attempt(decode_block, raw);
    attempt(decode_block_header, raw);
    attempt(decode_block_header_vector, raw);

    // Receipts / withdrawals / logs
    attempt(decode_receipt, raw);
    attempt(decode_untyped_receipt, raw);
    attempt(decode_log, raw);
    attempt(decode_bloom, raw);
    attempt(decode_withdrawal, raw);

    // Signatures + scalars + core
    attempt(decode_sc, raw);
    attempt(decode_bool, raw);
    attempt(decode_string, raw);
    attempt(decode_address, raw);

    return 0;
}
