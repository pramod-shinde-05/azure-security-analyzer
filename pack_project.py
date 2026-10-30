import os

OUTPUT_FILE = "project_content.txt"
EXCLUDED_DIRS = {".git", "__pycache__", "venv", "reports","source_code","database", "app-build","old_server_data","data",".venv"}
EXCLUDED_EXTENSIONS = {".pyc", ".ico", ".png", ".jpg", ".exe", ".dll", ".lib", ".obj",".db",".zip",".mp4",".log"}

def pack_project():
    root_dir = os.getcwd()
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as outfile:
        outfile.write("===========================================\n")
        outfile.write(f"PROJECT DOCUMENTATION DUMP\n")
        outfile.write(f"Root: {root_dir}\n")
        outfile.write("===========================================\n\n")

        for root, dirs, files in os.walk(root_dir):
            # Modify dirs in-place to skip excluded directories
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            
            for file in files:
                if file == OUTPUT_FILE:
                    continue
                    
                _, ext = os.path.splitext(file)
                if ext.lower() in EXCLUDED_EXTENSIONS:
                    continue
                
                # Check for "audit" or huge logs that we might have missed in dirs
                if "log" in file.lower() and ext == ".txt":
                    continue

                path = os.path.join(root, file)
                rel_path = os.path.relpath(path, root_dir)
                
                print(f"Adding: {rel_path}")
                
                outfile.write("="*80 + "\n")
                outfile.write(f"FILE PATH: {rel_path}\n")
                outfile.write("="*80 + "\n")
                
                try:
                    with open(path, "r", encoding="utf-8", errors="replace") as infile:
                        content = infile.read()
                        outfile.write(content)
                except Exception as e:
                    outfile.write(f"[ERROR READING FILE: {e}]")
                
                outfile.write("\n\n")

    print(f"\nSuccess! Project content saved to {OUTPUT_FILE}")
    input("Press Enter to exit...")

if __name__ == "__main__":
    pack_project()
