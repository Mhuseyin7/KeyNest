const secrets = [
  { key: "DATABASE_URL", status: "Active", updated: "Just now", by: "you@example.com", expiration: "—" },
  { key: "REDIS_URL", status: "Active", updated: "2 days ago", by: "team@example.com", expiration: "—" }
];

export default function Dashboard() {
  return <main><aside><h1>KeyNest</h1><nav>Dashboard<br />Projects<br />Environments<br />Secrets<br />Service Tokens<br />Team<br />Audit Log<br />Settings</nav></aside><section><header><div><p className="eyebrow">Project / Development</p><h2>Secrets</h2></div><button>Add secret</button></header><div className="tabs"><span className="active">Development</span><span>Staging</span><span>Production</span></div><input aria-label="Search secret keys" placeholder="Search secret key names" /><table><thead><tr><th>Key</th><th>Status</th><th>Updated</th><th>Updated by</th><th>Expiration</th></tr></thead><tbody>{secrets.map((secret) => <tr key={secret.key}><td><strong>{secret.key}</strong><small>••••••••••••</small></td><td><span className="badge">{secret.status}</span></td><td>{secret.updated}</td><td>{secret.by}</td><td>{secret.expiration}</td></tr>)}</tbody></table><p className="hint">Values are masked. Reveal is a deliberate, audited action; production may require reauthentication.</p></section></main>;
}

