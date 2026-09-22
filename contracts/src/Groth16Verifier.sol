// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax = 6804598917724183013779150440709781095782587675870776892606495173764226206225;
    uint256 constant alphay = 18107543673196603986146098257468081998959696518901656226037234403558201164436;
    uint256 constant betax1 = 12413663985328546115142744712918804509915135795466966262954375218842953512970;
    uint256 constant betax2 = 3137812689822985456886773949484507723017749742674313567881027120241549704661;
    uint256 constant betay1 = 11583226803122579040247652380792649606718818750765168360883455571563341128610;
    uint256 constant betay2 = 6594535535038074399132361632729423301939508827097734637547012570307896187620;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 8720082070939819954877774668539042443964172131648351579229566037269858046940;
    uint256 constant deltax2 = 17643949173508188496992173715874846714749203292318716902504948690895225681344;
    uint256 constant deltay1 = 14919986801987850228700925331908741964483540221172044382642314676857937340940;
    uint256 constant deltay2 = 16044968899971419972877271158891698560718203955461734665208978601403318137857;

    uint256 constant IC0x = 6180812261644712186546569712112181257990853685737402065743054396005671818473;
    uint256 constant IC0y = 666831085521770405686618769434299069529941943466717397938505948859546566551;

    uint256 constant IC1x = 19370049132239978927434681441915961583349404522797427997090787272467479330079;
    uint256 constant IC1y = 13482763750374805152190106859953039321596836871843514076183584636443769921436;

    uint256 constant IC2x = 16641551588278526723154956626984672206756253020343704408520357346116425877228;
    uint256 constant IC2y = 2530608050734688445133106735506995315513765601800961680361241118332687160205;

    uint256 constant IC3x = 17221293466311759054900793854532596016369603109687970168155316134502995917816;
    uint256 constant IC3y = 18742790156594936928229978164824043936370824528984351696918215954212515429173;

    uint256 constant IC4x = 3908667412730376400817049478701466058885743834164599624574969951956724527833;
    uint256 constant IC4y = 21639683113666499362402192718824522412883567664918551292226200821242544457136;

    uint256 constant IC5x = 12201430597686523580610792201532256644764486405227640153512338816404632867347;
    uint256 constant IC5y = 6434964620378050288548319749534823512720432934982236221206385743352531388756;

    uint256 constant IC6x = 976486225232513593879525660607811900259260083216565088444426173809336698054;
    uint256 constant IC6y = 3989816998312079300453379543457602914868636810117375783476063824248869449920;

    uint256 constant IC7x = 12151872535599040522664948875972967930324246833798592579183269577986484996413;
    uint256 constant IC7y = 21460429475671080671172485411778708509051258299297511808553595740945926252400;

    uint256 constant IC8x = 10966430738370984458603931493190028560770808960698053570539028820098452006896;
    uint256 constant IC8y = 20726530528247808328464923841531189221981734947759329999004460547755596674893;

    uint256 constant IC9x = 20353397563893873611290714411760808579778656666174735432630826610691942605429;
    uint256 constant IC9y = 14493489984136646269540668175402086845864532715019175798422395158982064629108;

    uint256 constant IC10x = 16922568471748630909231266121614791032807017278594645993497991512027110656128;
    uint256 constant IC10y = 6363355530327211153957617837237623434052519945162251025922264571738721115351;

    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[10] calldata _pubSignals
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(500000, 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(500000, 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))

                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))

                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))

                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))

                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))

                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))

                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))

                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))

                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))

                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(500000, 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            // CANONICAL_PROOF_COORDINATES: the pairing precompile accepts
            // field elements, but a proof has one canonical uint256 encoding.
            // Reject aliases such as pA.y + q and reject infinity points.
            function checkCoordinate(v) {
                if iszero(lt(v, q)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            let ax := calldataload(_pA)
            let ay := calldataload(add(_pA, 32))
            let bx0 := calldataload(_pB)
            let bx1 := calldataload(add(_pB, 32))
            let by0 := calldataload(add(_pB, 64))
            let by1 := calldataload(add(_pB, 96))
            let cx := calldataload(_pC)
            let cy := calldataload(add(_pC, 32))
            checkCoordinate(ax)
            checkCoordinate(ay)
            checkCoordinate(bx0)
            checkCoordinate(bx1)
            checkCoordinate(by0)
            checkCoordinate(by1)
            checkCoordinate(cx)
            checkCoordinate(cy)
            if iszero(or(ax, ay)) {
                mstore(0, 0)
                return(0, 0x20)
            }
            if iszero(or(or(bx0, bx1), or(by0, by1))) {
                mstore(0, 0)
                return(0, 0x20)
            }
            if iszero(or(cx, cy)) {
                mstore(0, 0)
                return(0, 0x20)
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            checkField(calldataload(add(_pubSignals, 64)))

            checkField(calldataload(add(_pubSignals, 96)))

            checkField(calldataload(add(_pubSignals, 128)))

            checkField(calldataload(add(_pubSignals, 160)))

            checkField(calldataload(add(_pubSignals, 192)))

            checkField(calldataload(add(_pubSignals, 224)))

            checkField(calldataload(add(_pubSignals, 256)))

            checkField(calldataload(add(_pubSignals, 288)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
