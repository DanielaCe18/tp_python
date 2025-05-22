def test_basic_shellcode():
    from shellcode_analyzer.analyzer import analyze_shellcode
    sc = b"\x90\x90\x90"  # NOP NOP NOP
    analyze_shellcode(sc)
