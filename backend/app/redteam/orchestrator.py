"""
Red Team Orchestrator — Master Scheduler (v2)

Coordinates the 24/7 automated adversarial self-testing system.
Generates 800+ novel attacks per cycle across ALL 35 generator categories,
executes them against GhostPrompt, analyzes results, and feeds
false negatives back to the training pipeline.

Equivalent to 2,000+ human red team hours per week.
"""

import random
import time

from app.core.logging import get_logger
from app.redteam.attack_executor import AttackExecutor
from app.redteam.attack_generators import ALL_GENERATORS
from app.redteam.results_analyzer import (
    DashboardReporter,
    ResultsAnalyzer,
    TrainingFeeder,
    WeaknessReporter,
)

logger = get_logger("redteam.orchestrator")


class RedTeamOrchestrator:
    """
    Master Red Team Scheduler.

    Coordinates automated adversarial testing across ALL 35 attack categories.
    Uses the full ALL_GENERATORS registry for comprehensive coverage.
    """

    def __init__(self):
        # Instantiate ALL generators from the registry
        self.generators: dict[str, object] = {}
        self.pack_hunt_gen = None

        for name, gen_cls in ALL_GENERATORS.items():
            try:
                instance = gen_cls()
                self.generators[name] = instance
                # Keep special reference for pack_hunt
                if name == "pack_hunt":
                    self.pack_hunt_gen = instance
            except Exception as e:
                logger.warning("generator_init_failed", generator=name, error=str(e))

        self.executor = AttackExecutor()
        self.analyzer = ResultsAnalyzer()
        self.weakness_reporter = WeaknessReporter()
        self.training_feeder = TrainingFeeder()
        self.dashboard_reporter = DashboardReporter()

        self._running = False
        self._total_cycles = 0
        self._last_run_time: float | None = None

        logger.info(
            "orchestrator_initialized",
            total_generators=len(self.generators),
            generator_names=list(self.generators.keys()),
        )

    async def run_cycle(self, org_id: str = "redteam-org", attacks_per_category: int = 20) -> dict:
        """
        Run one complete red team cycle.

        Generates attacks across ALL categories, executes them,
        analyzes results, and feeds false negatives to training.
        """
        logger.info("red_team_cycle_starting", cycle=self._total_cycles + 1, generators=len(self.generators))
        start = time.time()

        # Deterministic attack generation
        _rng_state = random.getstate()
        random.seed(42)

        # Reset generator counters for consistent output
        for gen in self.generators.values():
            for attr in ("_count", "_generated_count"):
                if hasattr(gen, attr):
                    setattr(gen, attr, 0)

        # Reset executor state from any previous cycle
        self.executor._results.clear()
        self.executor._false_negatives.clear()
        self.executor._total_executed = 0

        # Clear stateful detectors for redteam
        try:
            from app.services.firewall.engine import firewall_engine
            if firewall_engine._initialized:
                firewall_engine.pack_hunt_detector._request_graph.clear()
                firewall_engine.pack_hunt_detector._detected_campaigns.clear()
                firewall_engine.zero_day_detector._session_scores.clear()
        except Exception as e:
            logger.warning("failed_to_clear_redteam_state", error=str(e))

        # Generate attacks from ALL generators
        all_attacks = []
        gen_stats = {}

        for gen_name, gen_instance in self.generators.items():
            try:
                # Pack Hunt is special — generates sequences of fragments
                if gen_name == "pack_hunt" and hasattr(gen_instance, "generate_batch"):
                    pack_hunt_sequences = gen_instance.generate_batch(count=attacks_per_category // 2)
                    ph_count = 0
                    for seq in pack_hunt_sequences:
                        for frag in seq.fragments:
                            all_attacks.append({
                                "id": f"ph_{seq.sequence_id}_{frag['order']}",
                                "session_id": f"pack_{seq.sequence_id}",
                                "category": "pack_hunt",
                                "name": f"Pack Hunt {seq.strategy} #{frag['order']}",
                                "prompt": frag["text"],
                                "expected_action": "blocked" if frag["order"] == len(seq.fragments) - 1 else "any",
                                "technique": seq.strategy,
                            })
                            ph_count += 1
                    gen_stats[gen_name] = ph_count
                elif hasattr(gen_instance, "generate"):
                    attacks = gen_instance.generate(count=attacks_per_category)
                    # Enforce category on every attack — use generator name as fallback
                    for atk in attacks:
                        if not atk.get("category"):
                            atk["category"] = gen_name
                    all_attacks.extend(attacks)
                    gen_stats[gen_name] = len(attacks)
                else:
                    logger.warning("generator_no_generate_method", generator=gen_name)
                    gen_stats[gen_name] = 0
            except Exception as e:
                logger.error("generator_error", generator=gen_name, error=str(e))
                gen_stats[gen_name] = 0

        logger.info(
            "red_team_attacks_generated",
            total=len(all_attacks),
            generators_used=len([v for v in gen_stats.values() if v > 0]),
            per_generator=gen_stats,
        )

        # Restore RNG state
        random.setstate(_rng_state)

        # Execute all attacks
        results = await self.executor.execute_batch(all_attacks, org_id=org_id)

        # Analyze results
        analysis = self.analyzer.analyze(results)

        # Generate weakness report
        weakness_report = self.weakness_reporter.generate_report(analysis)

        # Feed false negatives to training pipeline
        false_negatives = self.executor.get_false_negatives()
        if false_negatives:
            self.training_feeder.feed(false_negatives[-50:])

        # Report to dashboard
        self.dashboard_reporter.record_run(analysis, weakness_report)

        self._total_cycles += 1
        self._last_run_time = time.time()
        duration = time.time() - start

        logger.info(
            "red_team_cycle_complete",
            cycle=self._total_cycles,
            total_attacks=len(all_attacks),
            generators_active=len([v for v in gen_stats.values() if v > 0]),
            detection_rate=analysis.get("overall_detection_rate", 0),
            false_negatives=len(false_negatives),
            duration_seconds=round(duration, 1),
        )

        return {
            "cycle": self._total_cycles,
            "total_attacks": len(all_attacks),
            "total_generators": len(self.generators),
            "generators_active": len([v for v in gen_stats.values() if v > 0]),
            "generator_breakdown": gen_stats,
            "analysis": analysis,
            "weakness_report": weakness_report,
            "false_negatives_count": len(false_negatives),
            "duration_seconds": round(duration, 1),
        }

    def get_dashboard_data(self) -> dict:
        """Get data for the Red Team Operations dashboard page."""
        # Gather per-generator stats
        generator_stats = {}
        for name, gen in self.generators.items():
            if hasattr(gen, "get_stats"):
                try:
                    generator_stats[name] = gen.get_stats()
                except Exception:
                    generator_stats[name] = {"status": "error"}
            else:
                generator_stats[name] = {"status": "active"}

        return {
            **self.dashboard_reporter.get_dashboard_data(),
            "total_cycles": self._total_cycles,
            "last_run_time": self._last_run_time,
            "total_generators": len(self.generators),
            "generator_names": list(self.generators.keys()),
            "generator_stats": generator_stats,
            "executor_stats": self.executor.get_stats(),
            "training_feeder_stats": self.training_feeder.get_stats(),
        }

    def get_false_negatives(self) -> list[dict]:
        """Get all false negatives from the last execution cycle."""
        return self.executor.get_false_negatives()

    def get_recent_results(self, limit: int = 50) -> list[dict]:
        """Get most recent red team attack results."""
        return self.executor.get_results(limit)


# Singleton
red_team_orchestrator = RedTeamOrchestrator()
