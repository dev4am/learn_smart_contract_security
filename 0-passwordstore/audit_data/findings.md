### [S-#] Storing the password on-chain makes it visible to anyone, and no longer private

**Description:** All data stored on-chain is visible to anyone, and can be read directly from the blockchain. The `PasswordStore::s_password` variable is intended to be a private varible and only accessed through the `PasswordStore::getPassword` function, which is intended to be only called by the owner of the contract.

We show one such method of reading any data off chain below.

**Impact:** Anyone can read the private password, severly breaking the functionality of the protocol.

**Proof of Concept:**

The below test case shows how anyone can read the password directly from the blockchain.

1. Create a locally running chain
```bash
make anvil
```

2. Deploy the contract to the chain
```bash
make deploy
```

3. Run the storage tool

We use `1` because that's the storage slot of `s_password` in the contract.

```bash
cast storage <ADDRESS_HERE> 1 --rpc-url http://127.0.0.1:8545
```

You'll get an output that looks like this:

`0x6d7950617373776f726400000000000000000000000000000000000000000014`

You can then parse that hex to a string with:

```bash
cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
```

And then you get an ouput of:

`myPassword`

**Recommended Mitigation:** Due to this, the overall architecture of the contract should be rethought.

### [S-#] Missing access control on `PasswordStore::setPassword`, making anyone can change the password.

**Description:** As an external function, `PasswordStore::setPassword` can be called by anyone. However, the natspec of the function and overall purpose of the smart contract is that `This function allows only the owner to set a new password.`

```javascript
function setPassword(string memory newPassword) external {
@>    // @audit - missing access control, should check if it is the owner call this.
    s_password = newPassword;
    emit SetNetPassword();
}
```

**Impact:** Anyone can set/change password of the contract.

**Proof of Concept:** Add the following to the `PasswordStore.t.sol` test suite.

<details>
<summary>Code</summary>

```javascript
function test_non_owner_can_not_set_password(address randomAddress) public {
    vm.assume(randomAddress != owner);
    vm.prank(randomAddress);
    
    string memory expectedPassword = "somePassword";
    passwordStore.setPassword(expectedPassword);

    vm.expectRevert();
}
```

</details>

The test will not fail as it should.

**Recommended Mitigation:** Add an access control conditional to the `PasswordStroe::setPassword` function

```javascript
if(msg.sender != s_owner) {
    revert PasswordStore__NotOwner();
}
```

### [S-#] The `PasswordStroe::getPassword` natspec indicates a parameter that doesn't exist, causing the natspec to be incorrect.

**Description:** The `PasswordStroe::getPassword` function signature is `getPassword()` while the natspec says it should be `getPassword(string)`.

**Impact:** The natspec is incorrect.

**Recommended Mitigation:** Remove the incorrect natpect line.

```diff
+   
-     * @param newPassword The new password to set.
```