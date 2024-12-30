# class Solution:
#     def romanToInt(self, s: str) -> int:
#         roman={"I": 1, "V": 5, "X": 10, "L": 50, "C": 100, "D": 500, "M": 1000}
#         subtract={"I":["V","X"], "X":["L","C"], "C":["D","M"]}
#         total = 0
#         i = 0
#         while i < len(s):
#             if i+1<len(s) and s[i] in subtract and s[i+1] in subtract[s[i]]:
#                 total = total + roman[s[i+1]] - roman[s[i]]
#                 i = i+2
#                 continue
#             total += roman[s[i]]
#             i = i+1
#         return total

n = 24

for i in str(n):
    print(int(i))

        