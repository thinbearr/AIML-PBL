"""Stage 4b: patch selection - Random/CVSS/EPSS rankings, Greedy, ILP and NSGA-II.

Common problem (synopsis Sec. 5.3.3): choose binary x_i to maximise sum(benefit_i x_i)
subject to  sum(cost_i x_i) <= budget,  sum(downtime_i x_i) <= downtime_limit,
and dependencies x_i <= x_req(i).  NSGA-II treats benefit and cost as two objectives.
"""
import numpy as np
from scipy import sparse
from scipy.optimize import milp, LinearConstraint, Bounds


def build_ext(patches, hosts, gamma):
    """Attack-path extension. Residual risk of host h is weighted by (1 + gamma * pf_h), where pf_h is the
    fraction of its upstream gateway's risk that is still unpatched. Patching a gateway therefore also
    lowers the risk counted on the hosts behind it - a product of decisions, hence non-linear."""
    hidx = {h: i for i, h in enumerate(hosts["host"])}
    A = np.zeros((len(patches), len(hosts)))
    A[np.arange(len(patches)), patches["host"].map(hidx).to_numpy()] = patches["benefit"].to_numpy()
    return {"A": A, "init": A.sum(0), "parent": hosts["parent"].to_numpy(int), "gamma": float(gamma)}


def ext_risk(X, ext):
    X = np.atleast_2d(X).astype(float)
    res = ext["init"] - X @ ext["A"]
    par = ext["parent"]
    ps = np.maximum(par, 0)
    pi = ext["init"][ps]
    pf = np.where((par >= 0) & (pi > 0), res[:, ps] / np.where(pi > 0, pi, 1.0), 0.0)
    return (res * (1 + ext["gamma"] * pf)).sum(1)


def ext_benefit(X, ext):
    X = np.atleast_2d(X)
    return ext_risk(np.zeros((1, X.shape[1])), ext)[0] - ext_risk(X, ext)


class Problem:
    def __init__(self, patches, budget, downtime_limit):
        self.benefit = patches["benefit"].to_numpy(float)
        self.cost = patches["cost"].to_numpy(float)
        self.dt = patches["downtime"].to_numpy(float)
        self.req = patches["requires"].to_numpy(int)
        self.budget, self.dt_limit = float(budget), float(downtime_limit)
        self.n = len(patches)
        self.ext = None

    def set_ext(self, ext):
        """Switch the objective to attack-path-aware risk (non-linear, so ILP no longer applies)."""
        self.ext = ext
        self.ext_base = float(ext_risk(np.zeros((1, self.n)), ext)[0])

    def feasible(self, x):
        x = np.asarray(x, bool)
        dep_ok = all(x[self.req[i]] for i in np.flatnonzero(x & (self.req >= 0)))
        return bool(self.cost[x].sum() <= self.budget + 1e-9 and self.dt[x].sum() <= self.dt_limit + 1e-9 and dep_ok)


def fill_by_order(pb, order):
    """Walk patches in `order`, adding each (plus its unmet prerequisite) while the limits allow."""
    x = np.zeros(pb.n, bool)
    c = d = 0.0
    for i in order:
        if x[i]:
            continue
        r = pb.req[i]
        need = [i] if (r < 0 or x[r]) else [r, i]
        nc = sum(pb.cost[k] for k in need)
        nd = sum(pb.dt[k] for k in need)
        if c + nc <= pb.budget and d + nd <= pb.dt_limit:
            x[need] = True
            c += nc
            d += nd
    return x


def select_random(pb, seed=0):
    return fill_by_order(pb, np.random.default_rng(seed).permutation(pb.n))


def select_by_score(pb, score):
    return fill_by_order(pb, np.argsort(-np.asarray(score), kind="stable"))


def select_greedy(pb):
    return fill_by_order(pb, np.argsort(-(pb.benefit / pb.cost), kind="stable"))


def select_ilp(pb, time_limit=30):
    n = pb.n
    dep = np.flatnonzero(pb.req >= 0)
    rows = [pb.cost, pb.dt]
    A = sparse.vstack([sparse.csr_matrix(np.vstack(rows)),
                       sparse.csr_matrix((np.r_[np.ones(len(dep)), -np.ones(len(dep))],
                                          (np.r_[np.arange(len(dep)), np.arange(len(dep))], np.r_[dep, pb.req[dep]])),
                                         shape=(len(dep), n))]).tocsr()
    ub = np.r_[pb.budget, pb.dt_limit, np.zeros(len(dep))]
    res = milp(-pb.benefit, constraints=LinearConstraint(A, -np.inf, ub), integrality=np.ones(n),
               bounds=Bounds(0, 1), options={"time_limit": time_limit, "mip_rel_gap": 1e-5})
    return np.round(res.x).astype(bool) if res.x is not None else np.zeros(n, bool)


# ----------------------------- NSGA-II ---------------------------------
def _repair(X, req):
    has = req >= 0
    Xt = X.T  # view; ufunc.at handles several dependents sharing one prerequisite
    np.logical_or.at(Xt, req[has], Xt[has])  # selecting a dependent patch forces its prerequisite
    return X


def _objectives(X, pb):
    ben = (pb.ext_base - ext_risk(X, pb.ext)) if pb.ext is not None else X @ pb.benefit
    cost, dt = X @ pb.cost, X @ pb.dt
    cv = np.maximum(0, cost - pb.budget) / pb.budget + np.maximum(0, dt - pb.dt_limit) / pb.dt_limit
    return np.column_stack([-ben, cost]), cv


def _dominates(F, cv):
    """Constraint-domination matrix D[i,j] = i dominates j."""
    fi, fj = F[:, None, :], F[None, :, :]
    pareto = (fi <= fj).all(2) & (fi < fj).any(2)
    feas = cv <= 0
    ci, cj = cv[:, None], cv[None, :]
    return np.where(feas[:, None] & feas[None, :], pareto,
                    np.where(feas[:, None] & ~feas[None, :], True,
                             np.where(~feas[:, None] & feas[None, :], False, ci < cj)))


def _sort_and_crowd(F, cv):
    n = len(F)
    D = _dominates(F, cv)
    dom_count = D.sum(0).astype(int)
    rank = np.full(n, -1)
    crowd = np.zeros(n)
    r, remaining = 0, np.ones(n, bool)
    while remaining.any():
        front = np.flatnonzero(remaining & (dom_count == 0))
        rank[front] = r
        for k in range(F.shape[1]):
            o = front[np.argsort(F[front, k])]
            span = F[o[-1], k] - F[o[0], k]
            crowd[o[0]] = crowd[o[-1]] = np.inf
            if span > 0 and len(o) > 2:
                crowd[o[1:-1]] += (F[o[2:], k] - F[o[:-2], k]) / span
        remaining[front] = False
        dom_count = dom_count - D[front].sum(0)
        dom_count[front] = -1
        r += 1
    return rank, crowd


def _fill_to(X, targets, pb, order):
    """Lamarckian step: top up each child with best benefit/cost patches until it reaches its target cost."""
    for k in range(len(X)):
        x = X[k]
        rem = targets[k] - pb.cost[x].sum()
        if rem <= 0:
            continue
        drem = pb.dt_limit - pb.dt[x].sum()
        ok = ~x & ((pb.req < 0) | x[np.maximum(pb.req, 0)])
        cand = order[ok[order]]
        if len(cand) == 0:
            continue
        add = cand[(np.cumsum(pb.cost[cand]) <= rem) & (np.cumsum(pb.dt[cand]) <= drem)]
        x[add] = True
    return X


def select_nsga2(pb, pop=100, gens=150, seed=0, callback=None, cost_cap=None):
    """Returns (front_X, front_benefit, front_cost) - the feasible non-dominated set."""
    rng = np.random.default_rng(seed)
    n = pb.n
    cap = cost_cap or pb.budget
    ratio = pb.benefit / pb.cost
    rorder = np.argsort(-ratio, kind="stable")
    # initial population: noisy ratio-ordered fills at varied budgets + greedy seed
    P = np.zeros((pop, n), bool)
    base = Problem.__new__(Problem)
    base.__dict__.update(pb.__dict__)
    for k in range(pop):
        base.budget = cap * (k + 1) / pop
        noisy = ratio * rng.lognormal(0, 0.6, n)
        P[k] = fill_by_order(base, np.argsort(-noisy))
    P = _repair(P, pb.req)
    F, cv = _objectives(P, pb)
    p_mut = 2.0 / n
    for g in range(gens):
        rank, crowd = _sort_and_crowd(F, cv)
        # binary tournament
        a, b = rng.integers(0, pop, (2, pop))
        win = np.where((rank[a] < rank[b]) | ((rank[a] == rank[b]) & (crowd[a] >= crowd[b])), a, b)
        par = P[win]
        mate = par[rng.permutation(pop)]
        mask = rng.random((pop, n)) < 0.5
        child = np.where(mask, par, mate)
        child ^= rng.random((pop, n)) < p_mut
        child = _repair(child, pb.req)
        child = _fill_to(child, np.minimum(par @ pb.cost, cap), pb, rorder)
        child = _repair(child, pb.req)
        Q = np.vstack([P, child])
        FQ, cvQ = _objectives(Q, pb)
        rank, crowd = _sort_and_crowd(FQ, cvQ)
        order = np.lexsort((-crowd, rank))[:pop]
        P, F, cv = Q[order], FQ[order], cvQ[order]
        if callback:
            callback(g, _front(P, F, cv))
    return _front(P, F, cv)


def _front(P, F, cv):
    ok = np.flatnonzero(cv <= 0)
    if len(ok) == 0:
        return P[:0], np.array([]), np.array([])
    rank, _ = _sort_and_crowd(F[ok], cv[ok])
    nd = ok[rank == 0]
    o = nd[np.argsort(F[nd, 1])]
    return P[o], -F[o, 0], F[o, 1]


def pick_from_front(front, budget):
    X, ben, cost = front
    ok = np.flatnonzero(cost <= budget + 1e-9)
    if len(ok) == 0:
        return np.zeros(X.shape[1], bool)
    return X[ok[np.argmax(ben[ok])]]
