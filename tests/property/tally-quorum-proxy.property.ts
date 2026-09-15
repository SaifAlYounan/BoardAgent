import fc from "fast-check";
import { describe, expect, it } from "vitest";

import { rational, tallyVote } from "../../lib/domain/src/index.js";

const rule = {
  approval: rational(1n, 2n),
  quorum: rational(1n, 2n),
  approvalDenominator: "yes_no" as const,
  abstentionsCountForQuorum: true,
  tieBehavior: "reject" as const
};

const choices = ["none", "yes", "no", "abstain"] as const;

describe("frozen tally/quorum/proxy properties", () => {
  it("exhausts every three-seat small case against an independent integer oracle", () => {
    for (const firstWeight of [1n, 2n]) {
      for (const secondWeight of [1n, 2n]) {
        for (const thirdWeight of [1n, 2n]) {
          const weights = [firstWeight, secondWeight, thirdWeight];
          for (const firstChoice of choices) {
            for (const secondChoice of choices) {
              for (const thirdChoice of choices) {
                const selected = [firstChoice, secondChoice, thirdChoice];
                const electorate = weights.map((weight, index) => ({
                  memberId: `m${String(index)}`,
                  role: "voting_member" as const,
                  weight,
                  eligible: true,
                  recused: false,
                  chair: false
                }));
                const ballots = selected.flatMap((choice, index) =>
                  choice === "none"
                    ? []
                    : [
                        {
                          principalMemberId: `m${String(index)}`,
                          casterMemberId: `m${String(index)}`,
                          choice,
                          source: "own" as const
                        }
                      ]
                );
                const actual = tallyVote(electorate, ballots, rule);
                const yes = selected.reduce(
                  (total, choice, index) => total + (choice === "yes" ? weights[index]! : 0n),
                  0n
                );
                const no = selected.reduce(
                  (total, choice, index) => total + (choice === "no" ? weights[index]! : 0n),
                  0n
                );
                const abstain = selected.reduce(
                  (total, choice, index) => total + (choice === "abstain" ? weights[index]! : 0n),
                  0n
                );
                const eligible = weights.reduce((total, weight) => total + weight, 0n);
                const quorumMet = (yes + no + abstain) * 2n >= eligible;
                const approvalMet = yes + no > 0n && yes !== no && yes * 2n >= yes + no;
                expect(actual.outcome).toBe(
                  !quorumMet ? "no_quorum" : approvalMet ? "approved" : "rejected"
                );
              }
            }
          }
        }
      }
    }
  });

  it("runs 100,000 seeded weighted electorates without violating conservation", () => {
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 1, max: 1_000_000_000 }), {
          minLength: 1,
          maxLength: 24
        }),
        fc.array(fc.constantFrom(...choices), { minLength: 1, maxLength: 24 }),
        (weights, generatedChoices) => {
          const electorate = weights.map((weight, index) => ({
            memberId: `m${String(index)}`,
            role: "voting_member" as const,
            weight: BigInt(weight),
            eligible: true,
            recused: false,
            chair: index === 0
          }));
          const ballots = electorate.flatMap((seat, index) => {
            const choice = generatedChoices[index % generatedChoices.length] ?? "none";
            return choice === "none"
              ? []
              : [
                  {
                    principalMemberId: seat.memberId,
                    casterMemberId: seat.memberId,
                    choice,
                    source: "own" as const
                  }
                ];
          });
          const result = tallyVote(electorate, ballots, rule);
          expect(result.yesWeight + result.noWeight + result.abstainWeight).toBe(
            result.participatingWeight
          );
          expect(result.participatingWeight).toBeLessThanOrEqual(result.eligibleWeight);
          expect(result.eligibleWeight).toBe(
            weights.reduce((total, weight) => total + BigInt(weight), 0n)
          );
        }
      ),
      { seed: 0x0b0a4d, numRuns: 100_000, endOnFailure: true }
    );
  }, 60_000);

  it("attributes 100,000 seeded proxy ballots to principals without changing their weight", () => {
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 1, max: 1_000_000_000 }), {
          minLength: 2,
          maxLength: 24
        }),
        fc.array(fc.constantFrom(...choices), { minLength: 1, maxLength: 24 }),
        fc.array(fc.boolean(), { minLength: 1, maxLength: 24 }),
        (weights, generatedChoices, proxyFlags) => {
          const electorate = weights.map((weight, index) => ({
            memberId: `m${String(index)}`,
            role: "voting_member" as const,
            weight: BigInt(weight),
            eligible: true,
            recused: false,
            chair: index === 0
          }));
          const proxyBallots = electorate.flatMap((seat, index) => {
            const choice = generatedChoices[index % generatedChoices.length] ?? "none";
            if (choice === "none") return [];
            const useProxy = proxyFlags[index % proxyFlags.length] ?? false;
            return [
              {
                principalMemberId: seat.memberId,
                casterMemberId: useProxy
                  ? electorate[(index + 1) % electorate.length]!.memberId
                  : seat.memberId,
                choice,
                source: useProxy ? ("proxy" as const) : ("own" as const)
              }
            ];
          });
          const directBallots = proxyBallots.map((ballot) => ({
            ...ballot,
            casterMemberId: ballot.principalMemberId,
            source: "own" as const
          }));
          expect(tallyVote(electorate, proxyBallots, rule)).toEqual(
            tallyVote(electorate, directBallots, rule)
          );
        }
      ),
      { seed: 0x50726f78, numRuns: 100_000, endOnFailure: true }
    );
  }, 60_000);
});
