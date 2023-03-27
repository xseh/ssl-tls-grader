from validity_checker import Validity
from sec_config import SecurityConfig
from certificate import Certificate
from rich.console import Console
from results import Result
import logging
from argparse import ArgumentParser

def run(header, h_style, module):
    result = Result(header, h_style)
    console.print("Running module set:", header, end="")
    result, total = module.run(result)
    console.print("\t[Complete]\n", style = "green")
    result.print()
    return total

def calculate_grade(total):
    if total < 25:
        grade = "[bold red]F[/bold red]"
    elif total < 50:
        grade = "[bold red]D[/bold red]"
    elif total < 75:
        grade = "[bold yellow]C[/bold yellow]"
    elif total < 90:
        grade = "[bold yellow]B[/bold yellow]"
    elif total < 100:
        grade = "[bold green]A[/bold green]"
    elif total == 100:
        grade = "[bold green]A+[/bold green]"
    return grade
    
console = Console()
console.print("Initialising program", end="")
config = SecurityConfig("google.com", 443)
try:
    asn1, pem = config.connect()
except TimeoutError:
    console.print("\t[Failed]", style = "red")
    logging.critical("Connection Timeout.")
    quit()
except ValueError:
    console.print("\t[Failed]", style = "red")
    logging.critical("No SSL certificate.")
    quit()
console.print("\t[Complete]", style = "green")

console.print("Loading certificate", end="\t")
certificate = Certificate(asn1, pem)
validity = Validity(certificate)
config.update(certificate)
console.print("\t[Complete]", style = "green", end = "\n\n")

certificate.info(console)

total = run("SSL/TLS Certificate Validity", "bold blue", validity) // 4
total += run("Website Security Configuration", "bold magenta", config)

console.print("[bold]Average score:[/bold]", str(total // 4))
console.print("[bold]Grade:[/bold]", calculate_grade(total // 4))