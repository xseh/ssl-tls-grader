from rich.console import Console
from rich.table import Table

class Result():
    def __init__(self, header, h_style):
        self.__console = Console()
        self.__table = self.__generate_table(h_style)
        self.__header = header
    
    def __del__(self):
        del self.__table
        
    def __generate_table(self, h_style):
        table = Table(show_header=True, header_style=h_style, width=100, show_lines=True)
        table.add_column("Module", width=20, style="bold")
        table.add_column("Description")
        table.add_column("Results")
        table.add_column("Score")
        return table
    
    def add_module(self, module, description, results, score):
        self.__table.add_row(module, description, results, score)
    
    def print(self):
        self.__console.print(self.__header, style="bold", justify="center", width=100)
        self.__console.print(self.__table)