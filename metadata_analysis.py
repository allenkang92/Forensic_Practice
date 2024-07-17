import os
import subprocess
import json
from datetime import datetime

def run_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout

def analyze_file(filename):
    # 파일 정보 얻기
    file_info = run_command(['file', filename])
    
    # exiftool로 메타데이터 얻기
    exif_info = run_command(['exiftool', '-j', filename])
    exif_data = json.loads(exif_info)[0]
    
    # 분석 결과
    analysis = {
        'filename': filename,
        'file_type': file_info.split(':')[1].strip(),
        'file_size': exif_data.get('FileSize', 'Unknown'),
        'modification_time': exif_data.get('FileModifyDate', 'Unknown'),
        'access_time': exif_data.get('FileAccessDate', 'Unknown'),
        'inode_change_time': exif_data.get('FileInodeChangeDate', 'Unknown'),
        'image_width': exif_data.get('ImageWidth', 'Unknown'),
        'image_height': exif_data.get('ImageHeight', 'Unknown'),
        'color_space': exif_data.get('ColorSpace', 'Unknown'),
        'bit_depth': exif_data.get('BitDepth', 'Unknown'),
    }
    
    # 포렌식 분석
    forensic_analysis = []
    
    # 숨김 파일 체크
    if filename.startswith('.'):
        forensic_analysis.append("File is hidden (starts with '.')")
    
    # 시간 정보 분석
    mod_time = datetime.strptime(analysis['modification_time'], "%Y:%m:%d %H:%M:%S%z")
    inode_time = datetime.strptime(analysis['inode_change_time'], "%Y:%m:%d %H:%M:%S%z")
    if (inode_time - mod_time).seconds > 0:
        forensic_analysis.append(f"Inode change time is {(inode_time - mod_time).seconds} seconds after modification time")
    
    # EXIF 데이터 체크
    if 'GPSPosition' not in exif_data and 'Make' not in exif_data:
        forensic_analysis.append("No camera or GPS data found. Possibly edited or from another source")
    
    analysis['forensic_notes'] = forensic_analysis
    
    return analysis

def main():
    filename = '.aurora.png'  # 분석할 파일 이름
    result = analyze_file(filename)
    
    print(json.dumps(result, indent=2))
    
    # 결과를 파일로 저장
    with open('metadata_analysis_result.json', 'w') as f:
        json.dump(result, f, indent=2)

if __name__ == "__main__":
    main()