def dao_nguoc_list(lst):
    return lst[::-1]

# Nhập danh sách từ người dùng
input_list = input("Nhập danh sách các số, các số cách nhau bằng dấu cách: ")
numbers = list(map(int, input_list.split(',')))

# Sử dụng hàm trong kết quả
so_lan_xuat_hien = dao_nguoc_list(numbers)
print("List sau khi đảo ngược: ", so_lan_xuat_hien)