#!/usr/bin/env python 

#TIL : DOCSTRINGS exists in python 

""""
Main entry point for Advanced Directory Enumeration
"""

# libs 
import sys # args
import os # dir traversal
import subprocess # cmds 
import argparse # the name says it 

def main():
    parser=argparse.ArgumentParser(
            description="Advanced Directory Enumeration - Choose your interface",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
            Examples:
            python run.py web                      # starts web interface
            python run.py cli https://example.com  # starts CLI tool
            python run.py test                     # checks the project dir 
            python run.py install                  # install dependencies [ from requirements.txt ]
            """
            )
    parser.add_arguments("mode",choices=["web","cli","test","install"],help="Mode to run the tool in")
    parser.add_arguments("target",nargs="?",help="Target URL [for CLI mode]")
    parser.add_arguments("--port",type=int,default=5000,help="Port for web server (default:5000)")

    # parse those args using sysargs [ i guess ]
    args = parser.parse_args()

    # cd
    serve_dir = os.path.join(os.path.dirname(__file__),"server")
    os.chdir(server_dir)

# OPTIONS 

    if args.mode=="install":
        printf("✴️ littting up your env by installing dependencies bro")
        try:
            # this is the good part
            subprocess.run([sys.executables,"-m","pip","install","-r","requirements.txt"],check=True)
            printf("✅ Dependencies installed bro")
        except subprocess.CalledProcessError as e:
            print(f"\n\n❌ fix this first: {e}\n\n\nEXITING . . .")
            sys.exit(1)


    elif args.mode=="test":
        print("🤖 Running test sir . . .")
        try:
            subprocess.run([sys.executable,"test_enum.py"],check=True)
        except subprocess.CalledProcessError as e:
            print(f"\n\n❌ Tests failed: {e}\n\n\n EXITING . . .")
            sys.exit(1)


    elif args.mode=="web":
        print("🌐 Starting web interface . . . \n")
        print(f"Client will be available at: http://localhost:{args.port}")
        print("Press Ctrl+c to stop the server [ this console ]")
        try:
            env=os.environ.copy()
            env["FLASK_PORT"]=str(args.port)
            subprocess.run([sys.executable,"app.py"],env=env)
        except KeyboardInterrupt:
            print("Daijobu da?👶\n\n❓What happened❓")
        except Exception as e:
            printf(f"‼️Error starting webserver: {e}\n\nEXITING . . .")
            sys.exit(1)


    elif args.mode=="cli":
        if not args.target:
            print(f"😄 give a target [URL] please . . .")
            print("Usage: python run.py cli http://ksurajsingh.github.io\n\nEXITING . . .")
            sys.exit(1)

        print("👨‍💻 Starting CLI interface . . .")
        try:
            subprocess.run([sys.executable,"cli.py",args.target]+sys.argv[3:],check=True)
        except subprocess.CalledProcessError as e:
            print(f"❌CLI error: {e}\n\nEXITING . . .")
            sys.exit(1)
        except KeyboardInterrupt:
            print(f"Daijobu da👶\n\n❓What happened bro❓")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n‼️CLI stopped‼️")


# Initialising the initiliser 😆 

if __name__ == "__main__":
    main()
