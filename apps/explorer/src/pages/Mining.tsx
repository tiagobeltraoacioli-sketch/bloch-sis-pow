import { useMemo, useState, ReactNode } from "react";
import { useAsync } from "../lib/hooks";
import { Loading, ErrorBox, Copyable, Stat } from "../components/ui";
import { fetchNetParams, HS_UNITS, POOL } from "../lib/mining";
import { parseBlochAddress, looksLikeBlochAddress } from "../lib/address";
import { fmtBloch, fmtHashrate, fmtNum, fmtDuration, fmtInt, timeAgo } from "../lib/format";

export function MiningPage() {
  const { data: net, error, loading } = useAsync(fetchNetParams, [], 30000);

  // calculator inputs
  const [hashInput, setHashInput] = useState("100");
  const [unitIdx, setUnitIdx] = useState(3); // GH/s default
  const [power, setPower] = useState(""); // watts
  const [cost, setCost] = useState(""); // $/kWh

  // wizard input
  const [addr, setAddr] = useState("");

  const userHs = useMemo(() => {
    const v = Number(hashInput);
    if (!isFinite(v) || v <= 0) return 0;
    return v * HS_UNITS[unitIdx][1];
  }, [hashInput, unitIdx]);

  const est = useMemo(() => {
    if (!net || !net.networkHs || !userHs) return null;
    const totalHs = net.networkHs + userHs; // include the user in the pie
    const share = userHs / totalHs;
    const blocksPerDay = share * (86400 / net.blockTimeSecs);
    const rewardBloch = net.minerRewardSats / 1e8;
    const blochPerDay = blocksPerDay * rewardBloch;
    const secsPerBlock = blocksPerDay > 0 ? 86400 / blocksPerDay : Infinity;
    return { share, blocksPerDay, blochPerDay, rewardBloch, secsPerBlock };
  }, [net, userHs]);

  const energy = useMemo(() => {
    const w = Number(power);
    const c = Number(cost);
    if (!isFinite(w) || w <= 0 || !isFinite(c) || c <= 0) return null;
    const kwhPerDay = (w / 1000) * 24;
    return { costPerDay: kwhPerDay * c, kwhPerDay };
  }, [power, cost]);

  const parsed = parseBlochAddress(addr);
  const addrTouched = addr.trim().length > 0;

  return (
    <div className="container">
      <div className="page-title">Mining calculator</div>
      <p className="muted" style={{ marginTop: -8, maxWidth: 760 }}>
        Estimate your blocks and BLOCH per day from the <strong>live</strong> network difficulty,
        block reward and block time. Everything below is an <em>estimate</em> under steady-state
        assumptions — real luck varies block to block.
      </p>

      {loading && !net && <Loading label="Reading live network params…" />}
      {error && !net && <ErrorBox error={error} />}

      {net && (
        <>
          {net.stalled && (
            <div className="banner-stale" style={{ marginTop: 14 }}>
              <span className="dot stale" />
              <div>
                <strong>Chain is stalled / difficulty is being tuned.</strong> The newest block is{" "}
                {net.freshestTs ? timeAgo(net.freshestTs) : "unknown age"}. Estimates use the last known
                difficulty and the {net.blockTimeSource === "measured" ? "measured" : "30s target"} block
                time — treat them as theoretical until the chain advances again.
              </div>
            </div>
          )}

          <div className="grid stat-grid" style={{ marginTop: 14 }}>
            <Stat label="Network hashrate" value={fmtHashrate(net.networkHs)} sub="live estimate" />
            <Stat label="Difficulty" value={fmtNum(net.difficulty, 0)} sub="current" />
            <Stat
              label="Block reward (miner)"
              value={fmtBloch(net.minerRewardSats, 4)}
              unit="BLOCH"
              sub={`subsidy ${fmtBloch(net.subsidySats, 2)} split`}
            />
            <Stat
              label="Block time"
              value={fmtDuration(net.blockTimeSecs)}
              sub={net.blockTimeSource === "measured" ? "measured avg" : "30s target (avg unstable)"}
            />
          </div>

          {/* ── Calculator ─────────────────────────────────────────── */}
          <div className="card pad-lg" style={{ marginTop: 18 }}>
            <div className="mine-form">
              <label className="mine-field">
                <span className="mine-lbl">Your hashrate</span>
                <div className="mine-inline">
                  <input
                    className="mine-input"
                    inputMode="decimal"
                    value={hashInput}
                    onChange={(e) => setHashInput(e.target.value)}
                    placeholder="100"
                  />
                  <select className="mine-select" value={unitIdx} onChange={(e) => setUnitIdx(Number(e.target.value))}>
                    {HS_UNITS.map(([u], i) => (
                      <option key={u} value={i}>
                        {u}
                      </option>
                    ))}
                  </select>
                </div>
              </label>
              <label className="mine-field">
                <span className="mine-lbl">
                  Power draw <span className="faint">(optional, W)</span>
                </span>
                <input
                  className="mine-input"
                  inputMode="decimal"
                  value={power}
                  onChange={(e) => setPower(e.target.value)}
                  placeholder="e.g. 3250"
                />
              </label>
              <label className="mine-field">
                <span className="mine-lbl">
                  Electricity <span className="faint">(optional, $/kWh)</span>
                </span>
                <input
                  className="mine-input"
                  inputMode="decimal"
                  value={cost}
                  onChange={(e) => setCost(e.target.value)}
                  placeholder="e.g. 0.12"
                />
              </label>
            </div>

            {!est ? (
              <div className="faint" style={{ marginTop: 16 }}>
                {net.networkHs
                  ? "Enter a positive hashrate to see estimates."
                  : "Network hashrate is unavailable right now, so share-based estimates can't be computed. Try again once the chain reports a hashrate."}
              </div>
            ) : (
              <div className="grid stat-grid" style={{ marginTop: 18 }}>
                <Stat
                  label="Your network share"
                  value={est.share >= 0.0001 ? fmtNum(est.share * 100, 3) + "%" : "<0.001%"}
                  sub={`${fmtHashrate(userHs)} of ${fmtHashrate(net.networkHs + userHs)}`}
                />
                <Stat
                  label="Est. blocks / day"
                  value={est.blocksPerDay >= 0.01 ? fmtNum(est.blocksPerDay, 2) : fmtNum(est.blocksPerDay, 4)}
                  sub={isFinite(est.secsPerBlock) ? `~1 block / ${fmtDuration(est.secsPerBlock)}` : "—"}
                />
                <Stat label="Est. BLOCH / day" value={fmtNum(est.blochPerDay, 4)} unit="BLOCH" sub="steady-state estimate" />
                <Stat
                  label="Est. BLOCH / month"
                  value={fmtNum(est.blochPerDay * 30, 3)}
                  unit="BLOCH"
                  sub={energy ? `energy ~$${fmtNum(energy.costPerDay * 30, 2)}/mo` : "add power for cost"}
                />
              </div>
            )}

            {energy && (
              <div className="rail" style={{ marginTop: 16 }}>
                <strong>Energy cost only.</strong> At {fmtNum(energy.kwhPerDay, 1)} kWh/day your electricity
                is about <strong>${fmtNum(energy.costPerDay, 2)}/day</strong>. BLOCH has no market price
                here — this explorer will not invent a fiat value or a profit figure. BLCH is neutral native
                gas, not an investment.
              </div>
            )}
          </div>

          {/* ── Setup wizard ───────────────────────────────────────── */}
          <div className="section-title" style={{ marginTop: 26 }}>Setup wizard</div>
          <p className="muted" style={{ marginTop: -6, maxWidth: 760 }}>
            Paste <strong>your own</strong> <code>bloch1q…</code> address to generate ready-to-run miner
            configs pointed at the Postern pool.
          </p>

          <div className="card pad-lg" style={{ marginTop: 12 }}>
            <label className="mine-field" style={{ maxWidth: 620 }}>
              <span className="mine-lbl">Your payout address</span>
              <input
                className={"mine-input mono" + (addrTouched && !parsed ? " bad" : parsed ? " good" : "")}
                value={addr}
                spellCheck={false}
                autoCapitalize="off"
                onChange={(e) => setAddr(e.target.value.trim())}
                placeholder="bloch1q…"
              />
            </label>
            {addrTouched && !parsed && (
              <div className="faint" style={{ marginTop: 6, color: "var(--red)" }}>
                {looksLikeBlochAddress(addr)
                  ? "Checksum/format not valid yet — a full Bloch address is bloch1q + 48 hex chars."
                  : "Not a Bloch address. It must start with bloch1q (mainnet) or bloch1t (testnet)."}
              </div>
            )}
            {parsed && <div className="faint" style={{ marginTop: 6, color: "var(--green)" }}>Valid {parsed.mainnet ? "mainnet" : "testnet"} address ✓</div>}

            <div className="warn-box" style={{ marginTop: 16 }}>
              <span className="warn-ico">⚠️</span>
              <div>
                Use the <strong>bare address</strong> as the miner username — <strong>no worker suffix</strong>.
                The pool rejects <code>address.worker</code>. Put the address in the <code>-u</code> field
                and any non-empty password (conventionally <code>x</code>) in <code>-p</code>.
              </div>
            </div>

            {(() => {
              const A = parsed ? parsed.address : "<your-bloch1q-address>";
              const ccminer = `ccminer -a sha256d -o ${POOL.stratum} -u ${A} -p x`;
              const minerd = `minerd -a sha256d -o ${POOL.stratum} -u ${A} -p x`;
              return (
                <div className="wiz-grid" style={{ marginTop: 18 }}>
                  <ConfigBlock title="ASIC / pool fields" disabled={!parsed}>
                    <FieldRow k="URL" v={POOL.stratum} />
                    <FieldRow k="Worker / user" v={A} />
                    <FieldRow k="Password" v="x" />
                    <FieldRow k="Algorithm" v="sha256d" />
                  </ConfigBlock>
                  <ConfigBlock title="ccminer (GPU)" cmd={ccminer} disabled={!parsed} />
                  <ConfigBlock title="minerd / cpuminer (CPU)" cmd={minerd} disabled={!parsed} />
                </div>
              );
            })()}

            {!parsed && (
              <div className="faint" style={{ marginTop: 12, fontSize: 12.5 }}>
                Enter a valid address above to enable copy-ready configs with your address filled in.
              </div>
            )}
          </div>

          <div className="rail" style={{ marginTop: 22 }}>
            <strong>Honest note.</strong> Bloch's proof-of-work is a SHAKE-256 hashcash gate with a small-k
            Module-SIS structural check. Difficulty, reward and block time above are read live from the
            node; your results depend on real network conditions and luck. Running a miner is a civic
            act on an ownerless network — not a promise of yield.
          </div>
        </>
      )}
    </div>
  );
}

function ConfigBlock({
  title,
  cmd,
  children,
  disabled,
}: {
  title: string;
  cmd?: string;
  children?: ReactNode;
  disabled?: boolean;
}) {
  return (
    <div className={"wiz-block" + (disabled ? " is-disabled" : "")}>
      <div className="wiz-head">
        <span>{title}</span>
        {cmd && <Copyable text={cmd} />}
      </div>
      {cmd ? <pre className="wiz-code">{cmd}</pre> : <div className="wiz-fields">{children}</div>}
    </div>
  );
}

function FieldRow({ k, v }: { k: string; v: string }) {
  return (
    <div className="wiz-field">
      <span className="wiz-k">{k}</span>
      <code className="wiz-v">{v}</code>
      <Copyable text={v} />
    </div>
  );
}
