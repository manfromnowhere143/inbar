# Mathematical Contract

## Hybrid physical model

For continuous state `z`, discrete mode `q`, input `u`, physical parameters `theta`, and evidence
`E`, the mission models:

```text
dz/dt = f_physics_q(z, u, theta) + r_phi(z, u, E)
q+    = T(q, event)
```

The learned residual `r_phi` may improve a physical model but cannot erase its constraints or act
as an independent verifier.

## Open-world posterior

Diagnosis maintains:

```text
p(H, z, theta | E),  H in {known mechanisms} union {unknown}
```

Unknown is a real decision state. Low likelihood under every known mechanism must increase unknown
mass or trigger abstention, not force a catalog label.

## Safe active test selection

For an approved test `a`, outcome `Y_a`, cost `C`, time `T`, and risk `R`:

```text
a* = argmax over a in A_safe:
     I(H; Y_a | E) / (C(a) + lambda*T(a) + mu*R(a))
```

Information gain is the reduction from current hypothesis entropy to expected posterior entropy.
Actions outside the frozen safety envelope are ineligible regardless of score.

## Selective uncertainty

Report proper scores and risk-coverage curves. Calibration must be measured by hardware, mission,
fault family, and operating regime. ECE alone is insufficient. Time-series conformal guarantees
are not assumed under dependence; coverage is empirical unless a valid dependent-data method is
proved for the frozen setting.

## Recovery verification

A recovery passes only if all three gates pass under an independent outcome authority:

1. the action is admissible;
2. the action targets the diagnosed mechanism;
3. the physical state reaches and remains inside a pre-registered settled-success set.

A learned score, verbal critique, or simulator outside its accredited decision-use domain cannot
substitute for settled execution.

## Value

Value is the 95% lower confidence bound of avoided engineer hours, downtime, tests, and expected
loss minus integration, compute, and false-action costs. A point estimate does not authorize a
commercial claim.

