from proxy_control_plane_truth import run_all_truth_tables


def test_proxy_control_plane_truth_tables():
    run_all_truth_tables()


if __name__ == "__main__":
    for name, value in list(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("ok")
