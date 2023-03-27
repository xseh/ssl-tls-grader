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
    result, score = module.run(result)
    console.print("\t[Complete]\n", style = "green")
    result.print()
    return score

def calculate_grade(score):
    print(score)
    if score < 25:
        grade = "[bold red]F[/bold red]"
    elif score < 50:
        grade = "[bold red]D[/bold red]"
    elif score < 75:
        grade = "[bold yellow]C[/bold yellow]"
    elif score < 90:
        grade = "[bold yellow]B[/bold yellow]"
    elif score < 100:
        grade = "[bold green]A[/bold green]"
    elif score == 100:
        grade = "[bold green]A+[/bold green]"
    return grade
    
def main(website):
    console = Console()
    console.print("[bold]Domain:[/bold]", website)
    console.print("Initialising program", end="")
    config = SecurityConfig(website, 443)
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
    return validity, config, console

#certificate.info(console)

websites = open("hidden/websites.csv", "r", encoding="utf-8").read().splitlines()
results = open("hidden/results.csv", "w", encoding="utf-8")

for website in websites:
    if "# " in website:
        category = website[2:]
    else:
        validity, config, console = main(website)
        score = run("SSL/TLS Certificate Validity", "bold blue", validity) // 4
        score += run("Website Security Configuration", "bold magenta", config)
        score //= 4

        console.print("[bold]Average score:[/bold]", str(score))
        console.print("[bold]Grade:[/bold]", calculate_grade(score))
        console.print()
        results.write(f"{category},{website},{score}\n")