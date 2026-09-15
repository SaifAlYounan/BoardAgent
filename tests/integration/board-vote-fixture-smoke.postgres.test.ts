import type { PoolClient } from "pg";
import { expect, it } from "vitest";
import {
  grantProxyInTransaction,
  revokeProxyInTransaction,
  withRequestTransaction
} from "../../lib/db/src/index.js";
import { withMigratedDatabase } from "../helpers/postgres-fixture.js";
import {
  confirmedBoardVoteProxyRevokeInput,
  confirmedVoteToolProxyGrantInput,
  seedBoardVoteReplacementFixture,
  seedVoteToolBallotFixture
} from "../helpers/vote-tool-ballot-fixture.js";
import {
  ORIGINAL_BOARDS_SQL,
  ORIGINAL_PROXY_SQL,
  ORIGINAL_VOTE_LINEAGE_SQL,
  ORIGINAL_VOTES_SQL
} from "../helpers/board-vote-read-original-sql.js";

const CASE = "supports the named normal board vote proxy and replacement fixture paths";
// Fixture foundation only. These original queries are independent of admission;
// this does not claim public confirmation, vote closing, tallying or issuance.
it(
  CASE,
  async () => {
    const observations: Record<string, unknown> = {};
    await withMigratedDatabase("bv_fixture_proxy", async (pool) => {
      const fixture = await seedVoteToolBallotFixture(pool);
      const read = <T>(work: (client: PoolClient) => Promise<T>) =>
        withRequestTransaction(pool, fixture.actorB.context, work, {
          assumeRole: "boardagent_server"
        });
      const initial = await read(async (client) => {
        expect((await client.query("select current_user::text as role")).rows).toEqual([
          { role: "boardagent_server" }
        ]);
        return (
          await client.query(ORIGINAL_PROXY_SQL, [
            fixture.voteId,
            fixture.actorB.memberId,
            fixture.actorB.memberId
          ])
        ).rows;
      });
      expect(initial).toEqual([{ items: [] }]);
      const grant = await confirmedVoteToolProxyGrantInput(pool, fixture, {
        actor: fixture.actorB,
        holderMemberId: fixture.actorA.memberId,
        idBase: 280000
      });
      await read((client) => grantProxyInTransaction(client, grant));
      const granted = await read(
        async (client) =>
          (
            await client.query(ORIGINAL_PROXY_SQL, [
              fixture.voteId,
              fixture.actorB.memberId,
              fixture.actorB.memberId
            ])
          ).rows
      );
      expect(granted).toHaveLength(1);
      expect(granted[0].items).toHaveLength(1);
      expect(granted[0].items[0]).toMatchObject({
        grant_id: grant.proxyGrantId,
        active: true,
        revocation: null
      });
      const revoke = await confirmedBoardVoteProxyRevokeInput(pool, fixture, {
        actor: fixture.actorB,
        proxyGrantId: grant.proxyGrantId,
        idBase: 281000
      });
      await read((client) => revokeProxyInTransaction(client, revoke));
      const revoked = await read(
        async (client) =>
          (
            await client.query(ORIGINAL_PROXY_SQL, [
              fixture.voteId,
              fixture.actorB.memberId,
              fixture.actorB.memberId
            ])
          ).rows
      );
      expect(revoked[0].items).toHaveLength(1);
      expect(revoked[0].items[0]).toMatchObject({
        grant_id: grant.proxyGrantId,
        active: false,
        revocation: {
          revocation_id: revoke.proxyRevocationId,
          effect: "revoked",
          reason: revoke.reason
        }
      });
      observations.proxy = {
        normalOpen: 1,
        normalGrant: 1,
        normalRevoke: 1,
        before: initial,
        granted,
        revoked
      };
    });
    // A separate fresh fixture preserves the exact old ballot/proxy/stage and
    // expected delivery dispositions of the copied replacement input builders.
    await withMigratedDatabase("bv_fixture_lineage", async (pool) => {
      const fixture = await seedBoardVoteReplacementFixture(pool);
      const read = <T>(work: (client: PoolClient) => Promise<T>) =>
        withRequestTransaction(pool, fixture.context, work, { assumeRole: "boardagent_server" });
      const lineage = (voteId: string) =>
        read(
          async (client) =>
            (await client.query(ORIGINAL_VOTE_LINEAGE_SQL, [voteId])).rows[0].items as Array<
              Record<string, unknown>
            >
        );
      expect(await lineage(fixture.originalVoteId)).toEqual([]);
      await fixture.replaceOnce();
      const middleBefore = await lineage(fixture.middleVoteId);
      expect(middleBefore).toHaveLength(1);
      expect(middleBefore[0]).toMatchObject({
        old_vote_id: fixture.originalVoteId,
        new_vote_id: fixture.middleVoteId
      });
      await fixture.appendSuccessor();
      const middle = await lineage(fixture.middleVoteId);
      expect(middle).toHaveLength(2);
      expect(middle.map((row) => [row.old_vote_id, row.new_vote_id])).toEqual([
        [fixture.originalVoteId, fixture.middleVoteId],
        [fixture.middleVoteId, fixture.successorVoteId]
      ]);
      const pages = await read(async (client) => {
        const boards = (
          await client.query(ORIGINAL_BOARDS_SQL, [fixture.actorA.memberId, null, null, 101])
        ).rows;
        const votes = (await client.query(ORIGINAL_VOTES_SQL, [fixture.boardId, null, null, 101]))
          .rows;
        return { boards, votes };
      });
      expect(pages.boards).toHaveLength(1);
      expect(pages.boards[0].item.board_id).toBe(fixture.boardId);
      expect(pages.votes).toHaveLength(3);
      expect(pages.votes.map((row) => row.item.vote_id).sort()).toEqual(
        [fixture.originalVoteId, fixture.middleVoteId, fixture.successorVoteId].sort()
      );
      observations.lineage = {
        normalOpen: 1,
        normalReplace: 2,
        middleBefore,
        middle,
        boards: pages.boards.length,
        votes: pages.votes.length
      };
    });
    process.stdout.write(`BOARD_VOTE_FIXTURE_SMOKE ${JSON.stringify(observations)}\n`);
  },
  90_000
);
