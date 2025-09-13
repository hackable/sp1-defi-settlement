// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISP1Verifier { function verify(bytes calldata proof, bytes calldata publicValues) external view returns (bool); }
interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }

library BalancesLeaf {
    function leafHash(address owner, bytes32 asset, uint128 cumulativeOwed) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(owner, asset, cumulativeOwed));
    }
}

library MerkleProofSorted {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            (bytes32 lo, bytes32 hi) = h < p ? (h, p) : (p, h);
            h = keccak256(abi.encodePacked(lo, hi));
        }
        return h == root;
    }
}

contract Ledger {
    ISP1Verifier public immutable verifier;
    bytes32 public balancesRoot;
    bytes32 public filledRoot;
    bytes32 public cancellationsRoot; // set of canceled orderIds (root)

    mapping(address => mapping(bytes32 => uint256)) public spent;

    event RootUpdated(
        bytes32 indexed oldBalancesRoot,
        bytes32 indexed newBalancesRoot,
        bytes32 prevFilledRoot,
        bytes32 newFilledRoot,
        bytes32 cancellationsRoot,
        uint32 matchCount
    );
    event Withdrawn(bytes32 indexed root, address indexed owner, bytes32 indexed asset, uint256 amount);

    constructor(address _verifier, bytes32 _genesisBalancesRoot, bytes32 _genesisFilledRoot, bytes32 _genesisCancellationsRoot) {
        verifier = ISP1Verifier(_verifier);
        balancesRoot = _genesisBalancesRoot;
        filledRoot = _genesisFilledRoot;
        cancellationsRoot = _genesisCancellationsRoot;
    }

    // publicValues ABI: (bytes32 balancesRoot, bytes32 prevFilledRoot, bytes32 filledRoot, bytes32 cancellationsRoot, uint32 matchCount)
    function updateRoot(bytes calldata proof, bytes calldata publicValues) external {
        require(verifier.verify(proof, publicValues), "invalid proof");
        (bytes32 newBalancesRoot, bytes32 prevFilledRoot, bytes32 newFilledRoot, bytes32 cancRoot, uint32 matchCount) =
            abi.decode(publicValues, (bytes32, bytes32, bytes32, bytes32, uint32));
        require(prevFilledRoot == filledRoot, "filled root mismatch");
        // Bind to the current cancellations view so the proof cannot ignore cancels.
        require(cancRoot == cancellationsRoot, "cancellations root mismatch");
        bytes32 oldBalancesRoot = balancesRoot;
        balancesRoot = newBalancesRoot;
        filledRoot = newFilledRoot;
        emit RootUpdated(oldBalancesRoot, newBalancesRoot, prevFilledRoot, newFilledRoot, cancellationsRoot, matchCount);
    }

    // Optional: admin hook to update cancellationsRoot (e.g., after on-chain cancels); add access control as needed.
    function setCancellationsRoot(bytes32 newCancellationsRoot) external {
        cancellationsRoot = newCancellationsRoot;
    }

    function withdraw(address owner, bytes32 asset, uint128 cumulativeOwed, uint256 amountToWithdraw, bytes32[] calldata proof) external {
        require(msg.sender == owner, "only owner");
        bytes32 leaf = BalancesLeaf.leafHash(owner, asset, cumulativeOwed);
        require(MerkleProofSorted.verify(proof, balancesRoot, leaf), "bad proof");
        uint256 already = spent[owner][asset];
        require(already + amountToWithdraw <= cumulativeOwed, "exceeds cumulative");
        spent[owner][asset] = already + amountToWithdraw;
        address token = address(uint160(uint256(asset)));
        require(IERC20(token).transfer(owner, amountToWithdraw), "transfer failed");
        emit Withdrawn(balancesRoot, owner, asset, amountToWithdraw);
    }
}
