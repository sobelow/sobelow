defmodule SobelowTest.XSS.ContentDispositionTest do
  use ExUnit.Case, async: true
  alias Sobelow.XSS.ContentDisposition

  for value <- [
        "attachment",
        " ATTACHMENT\t",
        ~S'attachment; filename="report.pdf"',
        ~S'attachment; filename="a; b, c.pdf"',
        ~S'attachment; filename="a\"b.pdf"',
        ~S'attachment; filename="a\\b.pdf"; size=12',
        "attachment; FILENAME = report.pdf",
        "attachment; filename*=UTF-8''r%C3%A9port.pdf",
        "attachment; filename*=iso-8859-1''r%E9port.pdf",
        ~S'attachment; filename="report.pdf"; filename*=UTF-8' <> "''report.pdf"
      ] do
    test "recognizes #{inspect(value)}" do
      assert ContentDisposition.attachment?(unquote(value))
    end
  end

  for value <- [
        nil,
        :attachment,
        "",
        "inline",
        "attachments",
        "attachment, inline",
        "attachment;",
        "attachment; filename",
        "attachment; filename=",
        "attachment; filename=a; FILENAME=b",
        "attachment; filename=a.pdf; size=1; SIZE=2",
        ~S'attachment; filename="unterminated',
        ~S'attachment; filename="a"b"',
        "attachment\r\ninline",
        "attachment; filename=\"a\nb\"",
        "attachment; filename=\"a\0b\"",
        "attachment; filename=\"a\\\rb\"",
        "\u00a0attachment",
        "attachment\u00a0",
        "attachment; filename=\"réport.pdf\"",
        "attachment; filename*=UTF-8''bad%XZ.pdf",
        "attachment; filename*=UTF-8''bad%FF.pdf",
        "attachment; filename*=UTF-8'en'report.pdf",
        "attachment; filename*=unknown''report.pdf",
        ~S'attachment; filename*="UTF-8' <> "''report.pdf\"",
        <<255>>
      ] do
    test "retains uncertainty for #{inspect(value)}" do
      refute ContentDisposition.attachment?(unquote(value))
    end
  end
end
