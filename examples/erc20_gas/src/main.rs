use alloy_provider::{network::Ethereum, ProviderBuilder, RootProvider};
use alloy_sol_types::{abi::token, sol, SolCall, SolValue};
use alloy_transport_http::Http;
use anyhow::{anyhow, Result};
use database::{AlloyDB, CacheDB};
use reqwest::Client;
use revm::{
    database_interface::WrapDatabaseAsync,
    handler::mainnet::validate_tx_against_account,
    primitives::{address, keccak256, Address, Bytes, TxKind, U256},
    specification::hardfork::Spec,
    state::{AccountInfo, EvmStorageSlot},
    wiring::{
        result::{EVMError, ExecutionResult, InvalidTransaction, Output},
        Block, EthereumWiring, Transaction,
    },
    Database, Evm, EvmHandler, EvmWiring,
};
use std::sync::Arc;

// Define ERC20 interface
sol! {
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function balanceOf(address owner) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
    }
}

// Constants
const TOKEN: Address = address!("1234567890123456789012345678901234567890");
const TREASURY: Address = address!("0000000000000000000000000000000000000001");
const ERC20_TRANSFER_SIGNATURE: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb]; // keccak256("transfer(address,uint256)")[:4]

// Handler register that overrides gas payment behavior
pub fn erc20_gas_handler_register<'a, EvmWiringT: EvmWiring, SPEC: Spec>(
    handler: &mut EvmHandler<'a, EvmWiringT>,
) where
    <EvmWiringT::Transaction as Transaction>::TransactionError: From<InvalidTransaction>,
{
    // Override deduct_caller to use ERC20 instead of ETH
    handler.pre_execution.deduct_caller = Arc::new(|ctx| {
        let caller = ctx.evm.inner.env.tx.common_fields().caller();
        let gas_limit = ctx.evm.inner.env.tx.common_fields().gas_limit();
        let gas_price = ctx.evm.inner.env.effective_gas_price();
        let token_amount = U256::from(gas_limit) * gas_price;

        let balance_slot: U256 = keccak256((caller, U256::from(3)).abi_encode()).into();

        let token_account = ctx
            .evm
            .inner
            .journaled_state
            .load_account(TOKEN, &mut ctx.evm.inner.db)
            .map_err(EVMError::Database)?;

        let storage_value = token_account
            .storage
            .get(&balance_slot)
            .expect("Balance slot not found")
            .present_value();

        if storage_value < token_amount {
            panic!("Insufficient balance");
        }

        token_account.data.storage.insert(
            balance_slot,
            EvmStorageSlot::new_changed(storage_value, storage_value.saturating_sub(token_amount)),
        );

        // Add tokens to treasury
        let treasury_balance_slot: U256 = keccak256((TREASURY, U256::from(3)).abi_encode()).into();
        let treasury_balance = token_account
            .storage
            .get(&treasury_balance_slot)
            .expect("Treasury balance slot not found")
            .present_value();

        token_account.data.storage.insert(
            treasury_balance_slot,
            EvmStorageSlot::new_changed(
                treasury_balance,
                treasury_balance.saturating_add(token_amount),
            ),
        );

        Ok(())
    });

    handler.post_execution.reimburse_caller = Arc::new(|ctx, gas| {
        let caller = ctx.evm.inner.env.tx.common_fields().caller();
        let gas_price = ctx.evm.inner.env.effective_gas_price();
        let refund_amount = gas_price * U256::from(gas.remaining() + gas.refunded() as u64);

        if refund_amount.is_zero() {
            return Ok(());
        }

        let token_account = ctx
            .evm
            .inner
            .journaled_state
            .load_account(TOKEN, &mut ctx.evm.inner.db)
            .map_err(EVMError::Database)?;

        // Return tokens from treasury to caller
        let treasury_balance_slot: U256 = keccak256((TREASURY, U256::from(3)).abi_encode()).into();
        let treasury_balance = token_account
            .storage
            .get(&treasury_balance_slot)
            .expect("Treasury balance slot not found")
            .present_value();

        token_account.data.storage.insert(
            treasury_balance_slot,
            EvmStorageSlot::new_changed(
                treasury_balance,
                treasury_balance.saturating_sub(refund_amount),
            ),
        );

        let caller_balance_slot: U256 = keccak256((caller, U256::from(3)).abi_encode()).into();
        let caller_balance = token_account
            .storage
            .get(&caller_balance_slot)
            .expect("Caller balance slot not found")
            .present_value();

        token_account.data.storage.insert(
            caller_balance_slot,
            EvmStorageSlot::new_changed(
                caller_balance,
                caller_balance.saturating_add(refund_amount),
            ),
        );

        Ok(())
    });

    handler.post_execution.reward_beneficiary = Arc::new(|ctx, gas| {
        let beneficiary = *ctx.evm.env.block.coinbase();
        let gas_price = ctx.evm.env.effective_gas_price();
        let reward = gas_price * U256::from(gas.spent() - gas.refunded() as u64);

        let token_account = ctx
            .evm
            .inner
            .journaled_state
            .load_account(TOKEN, &mut ctx.evm.inner.db)
            .map_err(EVMError::Database)?;

        // Transfer reward from treasury to beneficiary
        let treasury_balance_slot: U256 = keccak256((TREASURY, U256::from(3)).abi_encode()).into();
        let treasury_balance = token_account
            .storage
            .get(&treasury_balance_slot)
            .expect("Treasury balance slot not found")
            .present_value();

        token_account.data.storage.insert(
            treasury_balance_slot,
            EvmStorageSlot::new_changed(treasury_balance, treasury_balance.saturating_sub(reward)),
        );

        let beneficiary_balance_slot: U256 =
            keccak256((beneficiary, U256::from(3)).abi_encode()).into();
        let beneficiary_balance = token_account
            .storage
            .get(&beneficiary_balance_slot)
            .expect("Beneficiary balance slot not found")
            .present_value();

        token_account.data.storage.insert(
            beneficiary_balance_slot,
            EvmStorageSlot::new_changed(
                beneficiary_balance,
                beneficiary_balance.saturating_add(reward),
            ),
        );

        Ok(())
    });

    handler.validation.tx_against_state = Arc::new(|ctx| {
        let token_account = ctx
            .evm
            .inner
            .journaled_state
            .load_account(TOKEN, &mut ctx.evm.inner.db)
            .map_err(EVMError::Database)?;

        validate_tx_against_account::<EvmWiringT, SPEC>(
            token_account.data,
            &ctx.evm.inner.env.tx,
            &ctx.evm.inner.env.cfg,
        )
        .map_err(|e| EVMError::Transaction(e.into()))?;

        Ok(())
    });
}

fn main() -> Result<()> {
    Ok(())
}
