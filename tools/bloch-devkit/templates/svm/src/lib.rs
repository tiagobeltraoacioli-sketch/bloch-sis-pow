use solana_program::{account_info::{next_account_info, AccountInfo}, entrypoint,
    entrypoint::ProgramResult, program_error::ProgramError, pubkey::Pubkey};

entrypoint!(process_instruction);

// Counter accounts contain an authority pubkey followed by a little-endian u64.
// The client creates a rent-exempt, program-owned account before initialization.
pub fn process_instruction(program: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data != [0] && data != [1] { return Err(ProgramError::InvalidInstructionData); }
    let mut accounts = accounts.iter();
    let counter = next_account_info(&mut accounts)?;
    let authority = next_account_info(&mut accounts)?;
    if counter.owner != program { return Err(ProgramError::IncorrectProgramId); }
    if !counter.is_writable { return Err(ProgramError::InvalidAccountData); }
    if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    let mut bytes = counter.try_borrow_mut_data()?;
    if bytes.len() != 40 { return Err(ProgramError::InvalidAccountData); }
    if data == [0] {
        if !counter.is_signer { return Err(ProgramError::MissingRequiredSignature); }
        if bytes.iter().any(|byte| *byte != 0) {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
        bytes[..32].copy_from_slice(&authority.key.to_bytes());
        return Ok(());
    }
    if bytes[..32] != authority.key.to_bytes() {
        return Err(ProgramError::InvalidAccountData);
    }
    let value = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let next = value.checked_add(1).ok_or(ProgramError::ArithmeticOverflow)?;
    bytes[32..40].copy_from_slice(&next.to_le_bytes());
    Ok(())
}
