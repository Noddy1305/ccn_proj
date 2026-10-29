import io

from app import app


def test_index_lists_samples():
    r = app.test_client().get("/")
    assert r.status_code == 200 and b"forged_exam_cell.eml" in r.data


def test_sample_parse_shows_fields():
    r = app.test_client().post("/analyze", data={"sample": "forged_exam_cell.eml"})
    assert b"185.234.72.19" in r.data and b"examcell@srmist.edu.in" in r.data


def test_upload_invalid_shows_error():
    r = app.test_client().post("/analyze", data={"email": (io.BytesIO(b"hi"), "x.eml")},
                               content_type="multipart/form-data")
    assert b"does not look like a valid email" in r.data


def test_sample_path_traversal_blocked():
    r = app.test_client().post("/analyze", data={"sample": "../config.yaml"})
    assert b"Unknown sample" in r.data


def test_sender_card_shown_on_page(zone):
    zone.add_txt("_dmarc.srmist.edu.in", "v=DMARC1; p=reject")
    r = app.test_client().post("/analyze", data={"sample": "forged_exam_cell.eml"})
    assert b"Sender (SPF, DKIM, DMARC) check" in r.data and b"DMARC" in r.data and b"+25" in r.data


def test_selected_sample_is_kept_and_named():
    r = app.test_client().post("/analyze", data={"sample": "genuine_college.eml"}).data.decode()
    assert "Semester timetable published" in r
    assert 'value="genuine_college.eml" selected' in r
    assert "Showing results for <b>sample: genuine_college.eml</b>" in r


def test_points_table_total_and_legend():
    r = app.test_client().post("/analyze", data={"sample": "forged_exam_cell.eml"}).data.decode()
    assert "Points breakdown" in r and "Total score" in r and "How to read the score" in r
    assert "0-29" in r and "30-59" in r and "60-100" in r


def test_dropdown_has_placeholder_and_empty_choice_is_politely_rejected():
    c = app.test_client()
    assert "choose a sample" in c.get("/").data.decode()
    assert b"Please choose a .eml file first" in c.post("/analyze", data={"sample": ""}).data


def test_link_card_and_combined_points(zone):
    zone.live("verify-login.com", 3000)
    r = app.test_client().post("/analyze", data={"sample": "forged_exam_cell.eml"}).data.decode()
    assert "Link and domain check" in r and "Lookalike of a trusted domain" in r
    assert "+25" in r and "Total score" in r


def test_capped_total_is_explained_on_page(zone):
    zone.live("verify-login.com", 3)       # brand-new domain pushes the forged sample past 100
    r = app.test_client().post("/analyze", data={"sample": "forged_exam_cell.eml"}).data.decode()
    assert "capped at 100" in r and "100 / 100" in r
