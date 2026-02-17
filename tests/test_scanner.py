from scanner.scanner import scan_file


def test_basic_scan(tmp_path):
    # Create a temporary sample file
    test_file = tmp_path / "test.txt"
    test_file.write_text("password.txt here")

    result = scan_file(str(test_file))

    # Core output checks
    assert "file" in result
    assert "risk_score" in result
    assert "risk_band" in result
    assert "signals" in result

    # Sanity checks
    assert result["file"] == str(test_file)
    assert isinstance(result["risk_score"], int)
    assert result["risk_band"] in ["clean", "low", "medium", "high"]
