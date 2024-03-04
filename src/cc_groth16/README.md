# Commit carring groth 16

## How to use

[test_cc_groth16](./tests/test_cc_groth16.rs), [test_cc_groth16_with_voting_circuits](../zkvoting/voting/tests/test_cc_groth16_with_voting_circuits.rs) 를 참고해주세요.

### proof & commitment 생성
1. circuit 작성 시 첫번째 입력부터 openning key, commit에 사용될 inputs를 statement로 작성
2. pk, vk, pvk 생성
3. [Groth16 prove](./prover.rs)를 이용해 prove 생성
4. [commit](./commit.rs) 생성

### verify

- [verifer](./verifier.rs#verify_proof_with_commit)에 verify_proof_with_commit 함수 입력 참고하여 proof 검증. \
  (public_inputs은 commitment생성에 사용되지 않은 statement를 의미하며, public_inputs_start_index는 commit에 사용된 입력의 길이 + 1)

- [verfiy_commit](./commit.rs#verfiy_commit) 함수를 이용해 commitment가 올바르게 생성되었는지 체크할 수 있음
