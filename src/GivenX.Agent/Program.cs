using GivenX.Agent;

if (args.Any(x => x.Equals("--givenx-preflight", StringComparison.OrdinalIgnoreCase))) return;

using var mutex = new Mutex(true, @"Global\GivenXShield.Agent", out var first);
if (!first) return;
var engine = new MonitorEngine();
await engine.RunAsync();
