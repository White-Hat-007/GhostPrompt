# GhostPrompt Red Team Attack Generators — Master Registry
from app.redteam.attack_generators.comprehensive_generators import GENERATOR_REGISTRY
from app.redteam.attack_generators.extended_generators import EXTENDED_REGISTRY
from app.redteam.attack_generators.encoding_gen import EncodingGenerator
from app.redteam.attack_generators.multi_turn_gen import MultiTurnGenerator
from app.redteam.attack_generators.pack_hunt_gen import PackHuntGenerator
from app.redteam.attack_generators.pliny_gen import PlinyGenerator
from app.redteam.attack_generators.zero_day_gen import ZeroDayGenerator
from app.redteam.attack_generators.cross_agent_gen import CrossAgentGenerator
from app.redteam.attack_generators.coverage_generators import COVERAGE_GENERATORS

# Merge all registries
ALL_GENERATORS = {
    **GENERATOR_REGISTRY,
    **EXTENDED_REGISTRY,
    **COVERAGE_GENERATORS,
    "encoding": EncodingGenerator,
    "multi_turn": MultiTurnGenerator,
    "pack_hunt": PackHuntGenerator,
    "pliny": PlinyGenerator,
    "zero_day": ZeroDayGenerator,
    "cross_agent": CrossAgentGenerator,
}


