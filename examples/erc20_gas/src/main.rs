use alloy_provider::{network::Ethereum, ProviderBuilder, RootProvider};
use alloy_sol_types::{abi::token, sol, SolCall, SolValue};
use alloy_transport_http::Http;
use anyhow::{anyhow, Result};
use database::{AlloyDB, BlockId, CacheDB};
use reqwest::Client;
use revm::{
    database_interface::WrapDatabaseAsync,
    handler::mainnet::validate_tx_against_account,
    primitives::{address, keccak256, Address, Bytes, TxKind, U256},
    specification::hardfork::{LatestSpec, Spec},
    state::{AccountInfo, EvmStorageSlot},
    wiring::{
        result::{EVMError, ExecutionResult, InvalidTransaction, Output},
        Block, EthereumWiring, Transaction,
    },
    Database, Evm, EvmHandler, EvmWiring,
};
use std::sync::Arc;

type AlloyCacheDB =
    CacheDB<WrapDatabaseAsync<AlloyDB<Http<Client>, Ethereum, RootProvider<Http<Client>>>>>;

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
        let base_fee = ctx.evm.env.block.basefee();
        let reward = (gas_price - base_fee) * U256::from(gas.spent() - gas.refunded() as u64);

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

fn balance_of(token: Address, address: Address, alloy_db: &mut AlloyCacheDB) -> Result<U256> {
    sol! {
        function balanceOf(address account) public returns (uint256);
    }

    let encoded = balanceOfCall { account: address }.abi_encode();

    let mut evm = Evm::<EthereumWiring<&mut AlloyCacheDB, ()>>::builder()
        .with_db(alloy_db)
        .with_default_ext_ctx()
        .modify_tx_env(|tx| {
            // 0x1 because calling USDC proxy from zero address fails
            tx.caller = address!("0000000000000000000000000000000000000001");
            tx.transact_to = TxKind::Call(token);
            tx.data = encoded.into();
            tx.value = U256::from(0);
        })
        .build();

    let ref_tx = evm.transact().unwrap();
    let result = ref_tx.result;

    let value = match result {
        ExecutionResult::Success {
            output: Output::Call(value),
            ..
        } => value,
        result => return Err(anyhow!("'balanceOf' execution failed: {result:?}")),
    };

    let balance = <U256>::abi_decode(&value, false)?;

    Ok(balance)
}

fn transfer(
    from: Address,
    to: Address,
    amount: U256,
    token: Address,
    cache_db: &mut AlloyCacheDB,
) -> Result<()> {
    sol! {
        function transfer(address to, uint amount) external returns (bool);
    }

    let encoded = transferCall { to, amount }.abi_encode();

    let mut evm = Evm::<EthereumWiring<&mut AlloyCacheDB, ()>>::builder()
        .with_db(cache_db)
        .with_default_ext_ctx()
        .modify_tx_env(|tx| {
            tx.caller = from;
            tx.transact_to = TxKind::Call(token);
            tx.data = encoded.into();
            tx.value = U256::from(0);
        })
        .append_handler_register(
            erc20_gas_handler_register::<EthereumWiring<&mut AlloyCacheDB, ()>, LatestSpec>,
        )
        .build();

    let ref_tx = evm.transact_commit().unwrap();
    let success: bool = match ref_tx {
        ExecutionResult::Success {
            output: Output::Call(value),
            ..
        } => <bool>::abi_decode(&value, false)?,
        result => return Err(anyhow!("'transfer' execution failed: {result:?}")),
    };

    if !success {
        return Err(anyhow!("'transfer' failed"));
    }

    Ok(())
}

fn main() -> Result<()> {
    let rpc_url = "https://mainnet.infura.io/v3/c60b0bb42f8a4c6481ecd229eddaca27".parse()?;
    let client = ProviderBuilder::new().on_http(rpc_url);
    let alloy = WrapDatabaseAsync::new(AlloyDB::new(client, BlockId::latest())).unwrap();
    let mut cache_db = CacheDB::new(alloy);

    // Random empty account: From
    let account = address!("18B06aaF27d44B756FCF16Ca20C1f183EB49111f");
    // Random empty account: To
    let account_to = address!("0x21a4B6F62E51e59274b6Be1705c7c68781B87C77");

    let usdc = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");

    // USDC has 6 decimals
    let hundred_tokens = U256::from(100_000_000_000_000_000u128);

    let balance_slot = keccak256((account, U256::from(3)).abi_encode()).into();

    cache_db.insert_account_storage(usdc, balance_slot, hundred_tokens)?;
    cache_db.insert_account_info(
        account,
        AccountInfo {
            nonce: 0,
            balance: hundred_tokens,
            code_hash: keccak256(Bytes::new()),
            code: None,
        },
    );

    let balance_before = balance_of(usdc, account, &mut cache_db)?;

    // Transfer 100 tokens from account to account_to
    transfer(account, account_to, hundred_tokens, usdc, &mut cache_db)?;

    let balance_after = balance_of(usdc, account, &mut cache_db)?;

    println!("Balance before: {balance_before}");
    println!("Balance after: {balance_after}");

    Ok(())
}
