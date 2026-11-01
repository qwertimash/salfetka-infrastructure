"""A signed image must survive Docker classic/containerd ID differences."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from installer import panel
from installer.common import Failure, save


def archive(path, config=b'{"os":"linux","architecture":"arm64","rootfs":{"diff_ids":["sha256:fixture"]}}', *, tags=None, count=1):
    digest = hashlib.sha256(config).hexdigest()
    name = 'blobs/sha256/' + digest
    entry = {'Config': name, 'RepoTags': tags if tags is not None else ['salfetka-panel:0.6.2'], 'Layers': []}
    with tarfile.open(path, 'w') as target:
        for filename, data in [('manifest.json', json.dumps([entry] * count).encode()), (name, config)]:
            item = tarfile.TarInfo(filename); item.size = len(data)
            target.addfile(item, io.BytesIO(data))
    return 'sha256:' + digest


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.config_id = archive(self.root / 'image.tar')
        save(self.root / 'image.json', {'version': '0.6.2', 'platform': 'linux/arm64', 'image_id': self.config_id})

    def docker(self, local_id, *, altered=False, platform='linux/arm64'):
        def run(argv, **kwargs):
            if argv[:2] == ['docker', 'load']: return b''
            if argv[:3] == ['docker', 'image', 'save']:
                self.assertEqual(argv[-1], local_id)
                if altered: archive(argv[-2], b'{"different":"filesystem configuration"}')
                else: shutil.copyfile(self.root / 'image.tar', argv[-2])
                return b''
            if argv[3] == '--format={{.Id}}':
                self.assertEqual(argv[-1], 'salfetka-panel:0.6.2')
                return local_id.encode()
            self.assertEqual(argv[-1], local_id)
            return platform.encode()
        return run

    def test_classic_and_containerd_ids_verify_identical_config_bytes(self):
        for local_id in (self.config_id, 'sha256:' + 'b' * 64):
            with self.subTest(local_id=local_id), patch.object(panel, 'run', side_effect=self.docker(local_id)):
                result = panel.load_image(self.root)
                self.assertEqual(result['image_id'], local_id)
                self.assertEqual(result['version'], '0.6.2')

    def test_same_tag_cannot_substitute_different_image_contents(self):
        with patch.object(panel, 'run', side_effect=self.docker('sha256:'+'b'*64, altered=True)):
            with self.assertRaisesRegex(Failure, 'image_configuration_mismatch'): panel.load_image(self.root)

    def test_wrong_architecture_is_rejected_after_content_verification(self):
        with patch.object(panel, 'run', side_effect=self.docker(self.config_id, platform='linux/amd64')):
            with self.assertRaisesRegex(Failure, 'image_architecture_mismatch'): panel.load_image(self.root)

    def test_multiple_images_and_unsafe_references_fail_before_docker(self):
        for options in ({'count': 2}, {'tags': ['--unsafe']}, {'tags': []}):
            archive(self.root/'image.tar', **options)
            with self.subTest(options=options), patch.object(panel, 'run') as run:
                with self.assertRaises(Failure): panel.load_image(self.root)
                run.assert_not_called()
