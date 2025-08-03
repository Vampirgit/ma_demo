#!/usr/bin/env python3
import re
import sys
from collections import defaultdict

def analyze_torfs_output(input_file):
    # Data structures
    all_circuits = set()
    circuits_compromised = defaultdict(int)  # Tracks each unique compromised circuit type
    client_exposures = defaultdict(set)     # Tracks all compromise types per client
    
    # Relay statistics
    epoch_data = []
    current_epoch = None
    relay_stats = {
        'total_relays': 0,
        'total_guards': 0,
        'total_exits': 0,
        'adv_guards': 0,
        'adv_exits': 0
    }

    # Patterns
    patterns = {
        'epoch': re.compile(r'\[.*\] Entering simulation epoch with consensus from'),
        'relay_stats': re.compile(r'Total relays in consensus: (\d+), Valid/Running Guards: (\d+), Valid/Running Exits: (\d+)'),
        'adv_stats': re.compile(r'Total adversary guard relays: (\d+), Total adversary exit relays: (\d+)'),
        'circuit': re.compile(r'Client (\d+) uses the following circuit for a stream request: (\S+) (\S+) (\S+)')
    }

    with open(input_file) as f:
        for line in f:
            # Handle epoch information
            if patterns['epoch'].search(line):
                if current_epoch:
                    epoch_data.append(relay_stats.copy())
                current_epoch = line.strip()
                continue
                
            # Handle relay statistics
            relay_match = patterns['relay_stats'].search(line)
            if relay_match:
                relay_stats.update({
                    'total_relays': int(relay_match.group(1)),
                    'total_guards': int(relay_match.group(2)),
                    'total_exits': int(relay_match.group(3))
                })
                continue
                
            # Handle adversary statistics
            adv_match = patterns['adv_stats'].search(line)
            if adv_match:
                relay_stats.update({
                    'adv_guards': int(adv_match.group(1)),
                    'adv_exits': int(adv_match.group(2))
                })
                continue

            # Process circuit information
            circuit_match = patterns['circuit'].search(line)
            if circuit_match:
                client_id = int(circuit_match.group(1))
                guard, middle, exit_relay = circuit_match.groups()[1:]
                
                # Check compromised status
                g_comp = guard.endswith('*')
                m_comp = middle.endswith('*')
                e_comp = exit_relay.endswith('*')
                is_compromised = g_comp or m_comp or e_comp

                # Create unique circuit ID (not really unique but very unlikely to collide)
                circuit_id = (guard, middle, exit_relay)
                
                # Track compromised circuits
                if is_compromised and circuit_id not in all_circuits:
                    comp_type = (g_comp, m_comp, e_comp)
                    circuits_compromised[comp_type] += 1
                    client_exposures[client_id].add(comp_type)

                all_circuits.add(circuit_id)

    # Add final epoch data
    if current_epoch:
        epoch_data.append(relay_stats)

    # Calculate client counts per compromise type
    client_counts = defaultdict(int)
    for exposures in client_exposures.values():
        for comp_type in exposures:
            client_counts[comp_type] += 1

    return {
        'total_circuits': len(all_circuits),
        'compromised_circuits': sum(circuits_compromised.values()),
        'circuit_counts': dict(circuits_compromised),
        'total_clients': max(client_exposures.keys()) + 1 if client_exposures else 0,
        'compromised_clients': len(client_exposures),
        'client_counts': dict(client_counts),
        'client_exposures': client_exposures,
        'epoch_data': epoch_data
    }

def generate_report(results, output_file=None):
    """Generate a human-readable report"""
    output = []
    
    # All possible compromise combinations
    all_combinations = [
        (True, False, False),  # guard
        (False, True, False),  # middle
        (False, False, True),  # exit
        (True, True, False),   # guard+middle
        (True, False, True),   # guard+exit
        (False, True, True),   # middle+exit
        (True, True, True)     # all three
    ]
    
    def describe_compromise(g, m, e):
        parts = []
        if g: parts.append("guard")
        if m: parts.append("middle")
        if e: parts.append("exit")
        return '+'.join(parts) if parts else "none"

    # Circuit statistics
    output.append("CIRCUIT STATISTICS")
    output.append("==================")
    output.append(f"Total unique circuits: {results['total_circuits']}")
    output.append(f"Compromised circuits: {results['compromised_circuits']} ({results['compromised_circuits']/results['total_circuits']:.2%})")
    
    if results['compromised_circuits'] > 0:
        output.append("\nCOMPROMISED CIRCUIT BREAKDOWN:")
        for combo in all_combinations:
            count = results['circuit_counts'].get(combo, 0)
            if count > 0:
                output.append(f" - {describe_compromise(*combo)}: {count} circuits ({count/results['compromised_circuits']:.2%})")

    # Client statistics
    output.append("\nCLIENT STATISTICS")
    output.append("================")
    output.append(f"Total clients: {results['total_clients']}")
    output.append(f"Clients using compromised circuits: {results['compromised_clients']} ({results['compromised_clients']/results['total_clients']:.2%})")
    
    if results['compromised_clients'] > 0:
        output.append("\nCOMPROMISE TYPES USED BY CLIENTS:")
        for combo in all_combinations:
            count = results['client_counts'].get(combo, 0)
            if count > 0:
                output.append(f" - {describe_compromise(*combo)}: {count} clients ({count/results['total_clients']:.2%})")
        
        # Clients with multiple exposure types
        multi_exposure = sum(1 for exp in results['client_exposures'].values() if len(exp) > 1)
        if multi_exposure > 0:
            output.append(f"\nClients with multiple exposure types: {multi_exposure} ({multi_exposure/results['compromised_clients']:.2%})")

    # Relay statistics
    if results['epoch_data']:
        output.append("\nRELAY STATISTICS")
        output.append("================")
        num_epochs = len(results['epoch_data'])
        avg_total = sum(e['total_relays'] for e in results['epoch_data']) / num_epochs
        avg_guards = sum(e['total_guards'] for e in results['epoch_data']) / num_epochs
        avg_exits = sum(e['total_exits'] for e in results['epoch_data']) / num_epochs
        avg_adv_guards = sum(e['adv_guards'] for e in results['epoch_data']) / num_epochs
        avg_adv_exits = sum(e['adv_exits'] for e in results['epoch_data']) / num_epochs
        
        output.append(f"Number of epochs (started hours): {num_epochs}")
        output.append("\nAverage across all epochs:")
        output.append(f" - Total relays: {avg_total:.1f}")
        output.append(f" - Guard relays: {avg_guards:.1f} ({avg_guards/avg_total:.1%} of total)")
        output.append(f" - Exit relays: {avg_exits:.1f} ({avg_exits/avg_total:.1%} of total)")
        output.append(f" - Adversary guards: {avg_adv_guards:.1f} ({avg_adv_guards/avg_guards:.1%} of guards)")
        output.append(f" - Adversary exits: {avg_adv_exits:.1f} ({avg_adv_exits/avg_exits:.1%} of exits)")

    report = '\n'.join(output)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(report)
    return report

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_trace_file> <output_summary_file>")
        sys.exit(1)
    
    results = analyze_torfs_output(sys.argv[1])
    generate_report(results, sys.argv[2])
    print(f"Analysis complete. Report saved to {sys.argv[2]}")
